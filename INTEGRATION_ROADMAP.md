# Дорожная карта Veil

> Актуально на 2026-07-19. Это основной продуктовый и интеграционный план.
> [`ROADMAP.md`](ROADMAP.md) сохранён как исторический security/infra backlog;
> при расхождении приоритетов главным считается этот документ.

Базовый принцип Veil: интерфейс обязан правдиво показывать фактически
используемый режим защиты. Нельзя молча откатываться на plaintext или более
слабую криптосхему при ошибке распределения ключей. Если защищённая отправка
невозможна, она блокируется с понятным состоянием для пользователя.

Второй базовый принцип — автономность self-hosted инстанса. Уже настроенные
desktop/mobile клиенты, gateway, хранилище и локальные сервисы обязаны сохранять
основные функции в одной LAN при полном отсутствии WAN и внешнего control plane.
Потеря интернета может явно отключить push, updater или внешний media relay, но
не локальные сообщения и администрирование. Один инстанс использует один
canonical `(scheme, host, effective port)` origin и одну валидируемую TLS server
identity: split-horizon DNS направляет тот же hostname на LAN-адрес, не меняя
scheme, port или certificate trust. Клиент не подменяет origin IP-адресом,
альтернативным hostname или небезопасным HTTP.

Veil ещё не выпускался, поэтому runtime backward compatibility не является
продуктовым требованием. Устаревшие форматы, originless caches и UI-ветки нужно
удалять либо переводить явным cutover на текущую модель, а не поддерживать
параллельно. История миграций сохраняется только для воспроизводимой установки
схемы и проверяемого обновления development БД; она не оправдывает live fallback
или ослабление современных security/UX invariants.

Ближайший порядок работ:

1. Completion gate фаз 1–4C пройден и опубликован в
   [`docs/reviews/phase-1-4c-completion-gate.md`](docs/reviews/phase-1-4c-completion-gate.md).
2. Completion gate Phase 4D пройден и опубликован в
   [`docs/reviews/phase-4d-completion-gate.md`](docs/reviews/phase-4d-completion-gate.md).
3. Phase 4E implementation и automated gate выполнены; physical Veil Link /
   two-device matrix остаётся release evidence и не переоткрывает baselines 4A–4D.
4. Phase 2 product hardening закрыт: hard budget для rebuild/live mutation,
   exact SQLCipher navigation, независимый security review и полная проверочная
   матрица опубликованы в completion gate.
5. Phase 3B и 4P сохраняются отдельными незакрытыми product scopes: имеющийся
   desktop/transport foundation не заменяет physical attachment и native mobile
   push device matrices.
6. Продолжить Android Direct Preview: foundation/runtime 5A, receive/read,
   one-shot peer-prekey и shared idempotent send/outbox уже опубликованы;
   ближайший незакрытый gate — typed ACK deadline и transient-only reconnect.
   Точный checkpoint приведён в Phase 5.
7. Затем довести MLS runtime, звонки и release polish.

## Статус по фазам

| # | Фаза | |
|---|------|--|
| 1 | Kobalte — headless UI | закрыто: composite controls/focus/keyboard/ARIA унифицированы |
| 2 | Tantivy — локальный поиск | закрыто: RAM-only exact-origin index, bounded coverage и точная SQLCipher navigation |
| 3 | tus.io — загрузка файлов | protocol core закрыт; 3B product gate открыт до physical attachment matrix |
| 4 | UnifiedPush / ntfy | transport core готов; 4P device-client gate открыт до native mobile runtime и physical matrix |
| 4A | Группы, серверы, роли | access/crypto core закрыт; product IA/settings вынесены в 4E |
| 4B | Desktop UX & Appearance | закрыто: visual/a11y/scale/wallpaper/Windows bundle зелёные |
| 4C | Server Channel Crypto Decision | baseline закрыт: exact-device/offline/ACK/atomic recovery реализованы |
| 4D | Identity Island & Profiles | закрыто: product/security scope и completion gate зелёные |
| 4E | Veil Spaces Experience | implementation/automated gate закрыты; manual two-device Veil Link matrix pending |
| 5A | Android foundation | core runtime подключён: Keystore/SQLCipher, Node Access Pass, authenticated origin-bound sync; signed standalone APK и physical matrix открыты |
| 5B | Android messaging | receive/read, one-shot peer-prekey и idempotent native send/outbox опубликованы; reconnect/process-death открыт |
| 6 | OpenMLS | фундамент готов, runtime-ветвление выключено |
| 7 | LiveKit звонки | не начато |
| 8 | Полировка, релиз | частично: CI и Windows release workflow готовы |

---

## Продуктовая модель Veil Spaces

Veil — не набор разрозненных копий DM, Telegram-группы и Discord-сервера, а
система защищённых личных и совместных контекстов. Форма общения меняется, но
origin, identity, границы доступа и фактический crypto state остаются едиными и
видимыми пользователю.

Канонические продуктовые термины:

| Термин | Значение в интерфейсе | Текущий технический фундамент |
|---|---|---|
| **Home** | личный центр: поиск людей, друзья, запросы и Direct | UI-контекст, не создаваемый контейнер |
| **Direct** | защищённый разговор один на один | `dm`, X3DH + Double Ratchet |
| **Circle** | небольшая приватная группа с одной непрерывной беседой | `group`, Sender Keys v5 |
| **Space** | структурированное совместное пространство с участниками, ролями и Rooms | `server` как access/metadata container |
| **Room** | функциональный контекст внутри Space | text Room сейчас соответствует `channel` и отдельной conversation/security domain |
| **Veil Node** | self-hosted инфраструктура и canonical origin аккаунта | exact `(scheme, host, effective port)` origin |
| **Veil Link** | versioned приглашение в Space | scoped capability, не browser session и не identity proof |
| **Community** *(future)* | публикационное совместное пространство с постами, комментариями, реакциями и опросами | отдельный будущий product/schema/privacy/security contract; runtime отсутствует |

`Home`, `Direct`, `Circle`, `Space`, `Room`, `Veil Link` и `Veil Node` являются
продуктовым языком. Внутренние `dm/group/server/channel` в PostgreSQL, REST,
protobuf и Rust/Go не переименовываются механически: это точные protocol/storage
сущности, а не обязательство поддерживать старую информационную архитектуру.
Ни один UI-термин не меняет crypto mode, ACL, roster или history policy.

Community не является автоматической мутацией Circle и не выдаётся за готовую
часть Space runtime. Возможная будущая модель переиспользует общие identity,
origin и access invariants, но вводит новые content/history/moderation contracts
только после отдельного review. Браузерная версия мессенджера не входит ни в эту
модель, ни в будущий Community: web остаётся статическим product/docs/download
surface и узкими Veil Link/Share capability flows без account session и keys.

Один discriminated navigation state развивается до
`home(overview | friends | requests | direct(direct_id)) | circle(circle_id) |
space(space_id, room_id?)`:

- узкий левый остров содержит Home, смешанный список Circles/Spaces и единый
  вход создания/присоединения;
- второй остров показывает личную навигацию и Direct в Home, плавно сворачивается
  для Circle и показывает Rooms/управление для Space;
- центральный остров показывает выбранный Direct, Circle либо Room;
- правый остров сохраняет уже закрытую модель `Members ↔ Identity`;
- mobile использует ту же информационную модель, но нативный stack/sheet flow,
  а не буквальную копию desktop-колонок.

Direct начинается из поиска человека, Friends или Identity Island и не
считается «созданием пространства». Подключение/смена Veil Node — отдельная
account/origin ceremony и не смешивается с меню создания Circle/Space.

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

**Статус product hardening 2026-07-14: закрыто.** Независимый security re-review
завершён с `P0=0, P1=0, P2=0`; полная Rust/Go/Docker/frontend/visual/Windows
матрица зелёная. Контракт и фактические completion evidence зафиксированы в
[`phase-2-search-product-gate.md`](docs/reviews/phase-2-search-product-gate.md).

Полнотекстовый поиск по расшифрованным сообщениям. Индекс живёт только на
устройстве, на сервер ничего не уходит. Поисковый трафик сервер не видит.

**Актуальная модель:** Tantivy использует `RamDirectory`. После unlock индекс
перестраивается из SQLCipher, при lock исчезает вместе с процессной памятью;
старый постоянный индекс удаляется. Отдельного plaintext-индекса, marker-файла,
Windows ACL для search-директории и `search/v1`/`search/v2` больше нет.

Схема индекса: `id (STORED)`, `conversation_id (STORED + INDEXED)`, `sender_id (STORED + INDEXED)`, `body (TEXT)`, `timestamp (STORED + FAST для сортировки)`. Токенайзер — стандартный с lowercaser. Для кириллицы в v1 достаточно; multi-language остаётся отдельным улучшением.

Tauri команды: `search_messages`, `rebuild_search_index`,
`cancel_search_rebuild`, `clear_search_index`, `ensure_search_backfill`,
`get_search_coverage`, `get_search_result_context`.
Origin-scoped backfill выполняется после authenticated offline sync и может быть
безопасно повторён. Ручной rebuild отменяем; кандидат публикуется одной атомарной
заменой, поэтому поиск видит либо предыдущий полный индекс, либо новый полный
индекс, но не частично построенный snapshot.

Что надо помнить:
- Ротация ratchet ключей не требует реиндексации — plaintext не меняется, это важно задокументировать
- При удалении сообщения надо вызывать `Indexer::delete(id)` — сделано
- Индекс ограничен одновременно 64 MiB оценённого decrypted source и 250 000
  новейших непустых сообщений одного exact origin. Это bounded input для
  Tantivy, а не обещание, что allocator/index overhead равен ровно 64 MiB. При
  достижении границы UI честно сообщает частичное покрытие старой истории.
- Эти же hard bounds применяются внутри `veil-search` к live insert/edit/delete,
  а не только к rebuild projection. При переполнении сохраняется непрерывный
  newest slice; truncation остаётся видимой до полной очистки/rebuild.
- Rebuild читает SQLCipher newest-first через keyset pagination без старого
  молчаливого лимита 100 000 сообщений на conversation. Порядок
  `(effective timestamp, canonical message UUID)` совпадает с live budget;
  edit сохраняет исходную recency и не реинсертит старое сообщение как новое.
  Lock, смена account/origin, новый rebuild или явная Cancel инвалидируют
  candidate до публикации.
- Live mutation имеет monotonic mutation generation. Prepared rebuild не может
  затереть insert/edit/delete, случившийся во время SQLCipher extraction или
  Tantivy build: stale candidate отклоняется до swap, а текущий complete index
  остаётся опубликованным.
- Выбор результата повторно открывает exact `message_id + conversation_id +
  canonical_server_origin` из SQLCipher и публикует не более 200 сообщений
  вокруг цели. Native возвращает authoritative `dm | group | channel` и для
  Room — exact `server_id`; renderer не выводит тип контекста из одного UUID и
  не подменяет недоступный Room личным диалогом.
- Coverage опубликованного snapshot хранится рядом с RAM index в process state,
  выводится из того же committed Tantivy state и привязывается к exact native
  session/account/origin publication. Она очищается при lock/account/origin
  transition и отображается также после автоматического backfill. Устаревшие
  search/navigation ответы отсеиваются по query generation, UI session epoch и
  authenticated binding generation.
- Воспроизводимый release-profile test на 100 000 synthetic документов прошёл
  за 0.410 s на текущей Windows-машине 2026-07-14. Это evidence регрессии и
  bounded pipeline, а не универсальная гарантия времени для любого устройства.
- Смена схемы означает полный rebuild из SQLCipher; миграция отдельного search-файла не требуется.

Что закрыто: crate `veil-search`, подключённый в `veil-client::api`
(outgoing + incoming: insert, edit, delete). UI: `CommandPalette` на Kobalte
Dialog + Cmd/Ctrl+K, debounce, inline `<mark>` highlight, клавиатурная навигация,
доступная отмена rebuild, отдельные loading/error/empty состояния, точный
переход с центрированием найденного сообщения и валидируемые bounded
completion/coverage reports.

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

**Phase 3B — Attachment Experience (implementation checkpoint есть; product gate pending):**

Готово: security/schema review, versioned E2EE attachment payload, descriptor
commitment, O(1) XChaCha20 key wrapping внутри текущего Double Ratchet/Sender-Key
roster, атомарные private metadata/key rows в SQLCipher, live/offline receive,
нативный picker и drag-and-drop через одноразовый process-only capability,
bounded-memory upload/download, file bubble и безопасный Save.
Изображения JPEG/PNG/WebP декодируются и ре-энкодятся в PNG до шифрования, что
удаляет EXIF/container metadata. Сервер видит только ciphertext size, media id и
`application/octet-stream`; MIME и filename остаются в E2EE payload.

Аудио/видео preview использует отдельный `veilfile://` protocol. Нативный слой
повторно выводит MIME из аутентифицированного plaintext, принимает только
audio/video signatures и отдаёт WebView не более 8 MiB за range. Каждый range
расшифровывается только целыми AEAD chunks; plaintext не кэшируется на диске.
Capability привязан к текущим origin/session epoch, живёт не более 10 минут и
уничтожается вместе с ключом при lock/account switch.

Формальное закрытие не объявляется без внешнего доказательства, которое нельзя
честно заменить unit/integration тестом:
- physical two-device upload/download/tamper/resume/media-seek matrix.

Streaming uploader уже использует bounded-memory chunk pipeline до 2 ГиБ;
старый one-shot adapter не используется desktop attachment path.

Важные грабли, которые надо помнить:
- MIME spoofing: не доверять client-declared MIME. Ре-деривить на стороне получателя через `infer` crate перед рендером
- Resume после долгого оффлайна с другим IP: bearer-токен привязан к пользователю, не IP. Достаточно заминтить новый токен
- Disk fill от прерванных загрузок: `unfinished-upload-expiration` в tusd = 24 ч (UPLOAD_ABORT_TTL)
- Per-recipient K в группах: не шифровать файл заново для каждого участника.
  Шифруется один blob; ключ оборачивается по правилам текущего crypto roster.
  MLS exporter можно использовать только после реального включения MLS runtime.

---

## Phase 4 — UnifiedPush / ntfy push-уведомления

**Статус transport core 2026-07-14: исправлен и закрыт автоматическими
проверками; Phase 4P device-client gate остаётся открытым.** Повторный аудит
актуальной UnifiedPush specification выявил, что
прежний endpoint-only custom envelope не совместим с Android connector.
Migration 025 удаляет эти pre-release bindings и переводит транспорт на RFC 8291
Web Push (`aes128gcm`) с обязательными `p256dh`/`auth` и RFC 8292 VAPID.

Обычный push — только generic wake-up без sender/message/conversation metadata.
Web Push record всегда 2048 bytes. Клиент после получения выполняет обычный
authenticated E2E sync; plaintext preview и silent fallback отсутствуют.

**Серверный контракт:**
- подписанный GET VAPID public key и POST полного UnifiedPush subscription;
- random 256-bit challenge доставляется через новый канал и подтверждается
  подписанным account/origin-bound запросом;
- только validated + enabled + unmuted rows попадают в dispatcher projection;
- endpoint policy повторно проверяет URL/DNS при каждой отправке, запрещает
  redirects в private/reserved ranges и прунит 404/410;
- endpoint path, `p256dh` и `auth` не возвращаются list API и не логируются;
- если VAPID отсутствует, registration и delivery fail closed.

**Phase 4P — Device Push Clients:**
- Desktop management готов: list/policy/mute/delete; ручное добавление endpoint
  удалено, потому что ключевой материал обязан создавать native connector.
- Android `PushService` boundary реализован: принимает только decrypted 2048-byte
  wake и bounded account instance, не отдаёт endpoint/payload в JS. Register,
  signed confirm и bounded sync включаются только после account/origin-bound
  native auth runtime Phase 5A; до этого они fail closed и dormant.
- iOS APNS extension и App Group остаются отдельным iOS foundation.
- physical distributor/device matrix обязательна перед production release.

Security disposition и причины, по которым общий server transport key нельзя
встраивать в клиенты, зафиксированы в
[`docs/reviews/phase-4p-device-push-client-review.md`](docs/reviews/phase-4p-device-push-client-review.md).

Грабли:
- VAPID private key должен быть постоянным для deployment и одинаковым на всех
  gateway replicas; смена ключа требует явной перерегистрации устройств.
- iOS App Group keychain требует один access group для app + extension.
- Mute/DND и validation проверяются SQL projection до dispatcher fan-out.

---

## Phase 4A — Группы, серверы и роли

**Статус access/crypto core 2026-07-12: закрыто.** REST/DB/ACL, роли, инвайты,
участники, authoritative channel access, roster revisions и desktop-потоки
работают. Продуктовая информационная архитектура и зрелые server/channel
settings не выданы за готовый core: они выделены в **Phase 4E — Veil Spaces
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

- Отобразить закрытый technical core одной продуктовой моделью
  Home/Direct/Circle/Space/Room без параллельного legacy UI.
- Определить `Space-wide` и `Restricted` Room, future-only history для нового
  участника и поведение при role/access change. Оба режима остаются E2EE;
  internet-public/plaintext Room в текущий baseline не входит.
- Завершить Space/Room settings и правдивые crypto indicators.
- Добавить ручную desktop↔desktop matrix для create/join/leave/kick, нескольких
  физических устройств и offline reconnect поверх уже существующих automated
  exact-device/integration/race tests. Desktop↔Android evidence принадлежит
  Phase 5B/release gate и не создаёт циклическую зависимость до готового mobile
  runtime.

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
mediated TOFU/key transparency не входит в закрытую Phase 4D и требует отдельного
pre-production protocol/security gate; глобальный storage budget/compaction — к
Phase 8, а ручная физическая multi-device matrix — к Phase 4E/release gate.

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

**Статус 2026-07-13:** Phase 4D закрыта. Entry gate и
формальное решение опубликованы в
[`docs/reviews/phase-1-4c-completion-gate.md`](docs/reviews/phase-1-4c-completion-gate.md),
а финальный code freeze и зелёная проверочная матрица зафиксированы в
[`docs/reviews/phase-4d-completion-gate.md`](docs/reviews/phase-4d-completion-gate.md).
Реализованы canonical local identity foundation с authenticated origin/binding
fence, детерминированный Phaseprint и единый `UserAvatar`, Identity Island,
versioned text profile/cache/editor, локальная verification/identity-change flow,
relationship-scoped `ProfileUpdated`, identity-bearing local search DTO,
изолированный avatar pipeline и mobile Identity sheet. Full-workspace, Docker,
migration, visual и Windows release матрицы пройдены; остаточные риски явно
вынесены в completion gate и не скрываются статусом фазы.

Цель — дать одному человеку единое и узнаваемое представление во всех местах
Veil: собственный footer, друзья, DM, группы, сообщения, server members и
settings. Профиль называется **Identity Island** и продолжает язык Phase Shift,
а не копирует banner/popover Discord.

Phase 4D отслеживалась как шесть прямых продуктовых deliverables без вложенных
«фаз внутри фаз»:

1. Identity foundation: durable origin binding, hard namespace cutover и
   удаление originless runtime legacy.
2. Детерминированный Phaseprint и единый `UserAvatar`.
3. Identity Island, все точки открытия, плавная навигация и переходы в DM.
4. Versioned text profile, origin-scoped search и privacy/security review.
5. Identity Proof, локальная verification и blocking identity-change flow.
6. Изолированный безопасный avatar pipeline, mobile adaptation и финальный
   completion gate.

Малые migration/security commits внутри deliverable являются только
проверяемыми Git-checkpoint'ами, а не новыми уровнями roadmap.

### Entry gate 4D

Gate-review выполнен 2026-07-12 со ссылками на тесты, bundle и local migration
smoke:

| Предыдущая фаза | Gate | Scope disposition |
|---|---|---|
| 1 | пройден | composite controls/focus/keyboard закрыты; простые semantic HTML controls допустимы |
| 2 | пройден | RAM-only поиск и rebuild из SQLCipher работают; memory budget был entry-gate hardening и закрыт Phase 2 product gate 2026-07-14 |
| 3 | пройден | encrypted upload core закрыт; attachment UX/2 GiB streaming — Phase 3B |
| 4 | пройден | encrypted transport core закрыт; device `K_push` clients — Phase 4P |
| 4A | пройден | authoritative access/roster core закрыт; Veil Spaces IA/settings — Phase 4E |
| 4B | пройден | AppShell cleanup, scale/contrast/a11y/visual matrix и NSIS bundle зелёные |
| 4C | пройден | exact-device roster, multi-generation retention, receipts и atomic recovery реализованы |

Незавершённые client/product куски не исчезли: Phase 3B, 4P и 4E являются
явными владельцами. Entry gate разрешал Phase 4D foundation, но требовал
отдельных критериев готовности для network profile/avatar pipeline; эти критерии
выполнены и зафиксированы в финальном completion gate.

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

Pre-release namespace cutover завершён для conversation/message/pending/roster/
reaction state: одинаковые bare UUID на разных origins адресуются разными
canonical namespaces, а originless development rows не получают активный origin
по догадке. Friend/request/group/server consumers используют typed locator-bearing
snapshots. Исторический автор сохраняется с авторитетным контекстом и после выхода
из roster показывается как `Former member`, без присвоения текущих ролей/presence.

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

Этот cutover не меняет ciphertext, ratchets, Sender Keys, ACL либо rotation
contract. Consumer normalization, colliding origin namespaces, `Former member`
и generation-bound проверка identity-mutating REST результатов закрыты.
Originless server cache не возвращён: server/channel/member/role presentation
загружается свежим authenticated REST до отдельной origin-scoped cache schema.

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

Этот блок затронул адресацию локального хранения сообщений. До cutover были
зафиксированы отдельное schema/crypto explanation, backup development БД и
restart/collision/recovery test matrix; ciphertext и криптографический протокол
не изменялись.

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
смене. Remote/data/network image URL отклоняются. Native загружает только
same-origin avatar asset, проверяет и нормализует PNG/JPEG с удалением metadata,
а renderer получает локальный `blob:` URL, который decode-ится над уже
отрисованным Phaseprint; error/abort не даёт broken-image flash.
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
checkpoint'ы ниже закрыли text profile/event/proof части и изолированный avatar
pipeline.

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
6. **Закрыто:** изолированный avatar pipeline и mobile adaptation.

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

## Phase 4E — Veil Spaces Experience

**Статус 2026-07-14:** implementation complete; automated completion gate зелёный.
Формальное закрытие ожидает только ручную физическую desktop↔desktop матрицу,
которую нельзя честно заменить двумя процессами на одном компьютере. Evidence:
[`phase-4e-completion-gate.md`](docs/reviews/phase-4e-completion-gate.md).
Фаза превращает уже закрытый access/crypto core 4A/4C
в одну законченную продуктовую модель, но не меняет ciphertext, Double Ratchet,
Sender Keys v5 либо rotation contract. Authoritative ACL остаётся единственным
источником доступа; 4E лишь ужесточает invite defaults и не вводит параллельную
permission model.

Текущий desktop является исходной точкой, а не целевой IA: `ServerRail` имеет
раздельные create/join actions, Home одновременно показывает Friends,
`Messages`, `DM/Group` и `All/DMs/Groups`, а Circle живёт внутри списка
conversation. Mobile prototype буквально листает `servers → channels → chat →
members`. При cutover эти параллельные пути удаляются, а не остаются как legacy
вариант.

Phase 4E отслеживается как пять прямых deliverables. Их небольшие Git-checkpoint
commits не являются вложенными фазами.

### Deliverable: product model и единая навигация

- Ввести один discriminated route:
  `home(overview | friends | requests | direct(direct_id)) | circle(circle_id) |
  space(space_id, room_id?)`.
  Route всегда живёт внутри точного authenticated origin/binding и не переносит
  ID между Veil Nodes.
- Левый остров содержит Home, смешанный прокручиваемый список Circles/Spaces,
  быстрый поиск/переключение и одну кнопку `+`. Accessible name каждой строки
  сообщает не только имя, но и тип `Circle`/`Space`.
- Второй остров:
  - Home — поиск людей/разговоров, Friends, Requests и Direct;
  - Circle — плавно сворачивается, расширяя центральную беседу;
  - Space — показывает доступные Rooms, категории и управление текущим Space.
- Центральный остров показывает Direct, Circle либо выбранный Room. Правый
  сохраняет готовый route `closed | members | identity`.
- Морфинг/сворачивание занимает ориентировочно 180–240 ms без layout jump.
  Перед скрытием фокус переводится в остающийся контекст, скрытый DOM становится
  `inert`, а focus/scroll/selection/draft восстанавливаются детерминированно.
  Reduced motion убирает перемещение без появления второй активной оболочки.
- Kick/leave/delete, потеря роли/Room access или смена binding сначала инвалидирует
  route/action epoch, останавливает sync/send, блокирует composer и закрывает
  Members/Identity недоступного контекста. Потерянный Circle/Space возвращает в
  Home; недоступный Room — в подтверждённый Space empty state либо первый свежий
  authoritative доступный Room. Draft остаётся только origin/conversation-scoped
  и не может быть отправлен без новой ACL/roster validation; stale completion не
  имеет права воскресить старый route.

### Deliverable: создание, поиск и вход

- Единый `+` предлагает только `Create Circle`, `Create Space` и
  `Join with Veil Link`. Старые `DM/Group`, `All/DMs/Groups`, отдельная кнопка
  создания group и второй join-server icon удаляются после переноса сценариев.
- Direct начинается из person search, Friends, Identity Island или найденного
  authoritative message author. Голый user UUID и conversation ID не являются
  account locator.
- Create Circle включает member picker минимум с одним exact origin-scoped
  account locator. Initial creator+selected-member roster подтверждается
  атомарно; одночленный orphan не показывается как успешно созданный Circle.
  `Add people` из Friends/Identity после создания повторно проверяет locator,
  authoritative roster и Sender-Key rotation до разрешения отправки.
- Circle остаётся одной приватной непрерывной беседой без искусственного списка
  Rooms. Автоматического Circle → Space morph или смены crypto mode нет; будущая
  явная конверсия требует отдельного data/history/security contract.
- Подключение или смена Veil Node остаётся отдельным account/origin flow:
  создание социального контекста не может молча переключить origin либо vault.

### Deliverable: Space и Room experience

- Space settings завершают overview, members, roles, Veil Links и
  security/history explanation; Room settings — имя/topic, порядок, role/member
  access и history policy. Общий полнотекстовый Space Audit Log не является
  скрытым gate 4E; обязательны только bounded Veil Link lifecycle events без
  raw token.
- Существующий `PermBanMembers` получает недостающие authoritative persistence,
  signed management API и UI для ban/unban. Это moderation enforcement внутри
  текущей permission model, а не новый crypto trust signal.
- Вместо двусмысленного `public/private channel` интерфейс использует:
  - `Space-wide` — Room доступен всем текущим участникам Space и остаётся E2EE;
  - `Restricted` — Room доступен только разрешённым ролям/участникам и тоже E2EE.
- Text Room остаётся отдельной Sender Keys v5 security domain. UI одинаково
  правдиво показывает `encrypted`, `rotation pending`, `quarantined` и
  `unavailable`; future-only history не обещает старые ключи новому участнику.
- Room type делается расширяемым, но 4E активирует только реально работающий
  Text Room. Voice Room принадлежит Phase 7; Board/Stage, posts, comments,
  reactions/polls и community mode не показываются как доступные функции до
  отдельного product/schema/privacy/security review.
- В первом 4E contract используется только deterministic Space mark с seed из
  canonical origin + Space ID. Он декоративный, не identity proof и не trust
  indicator; person Phaseprint не переиспользуется. Space image asset отложен
  до отдельного same-origin ingest/privacy/image-decoder review, remote URL
  запрещены.

### Deliverable: Veil Link и invitation portal

Текущий invite foundation нельзя просто переименовать: восьмисимвольный код
имеет 48 бит энтропии, хранится и повторно листится открытым текстом,
`veil://invite/{code}` не содержит origin, unsigned preview возвращает слишком
широкий server DTO, а native deep-link flow не реализован. Публичный Veil Link
получает pre-release hard cutover без поддержки старого формата:

- versioned typed capability всегда содержит exact canonical origin; secret
  имеет минимум 128 бит энтропии, хранится только как hash и показывается один
  раз при создании. Управление/revoke выполняются по отдельному invite ID;
- отдельный непрогнозируемый public selector также создаётся CSPRNG и имеет не
  менее 128 бит энтропии; DB invite ID или последовательный ключ им не является.
  Selector может открыть только минимальный allowlisted preview. Raw join secret
  не попадает в access/error logs, analytics, third-party requests или
  `Referer`; точное URL/wire представление фиксируется отдельным schema/API/
  privacy/security review до реализации;
- origin-hosted HTTPS portal целевого Veil Node показывает Space name,
  разрешённое владельцем описание/Space mark, exact origin, срок и join policy
  (`v1: immediate membership only after explicit native confirmation`) только
  как text/deterministic mark. Owner UUID, member list,
  created-at и произвольные image URL не выдаются; ответ использует `no-store`,
  `Referrer-Policy: no-referrer`, strict CSP/text escaping и не содержит
  third-party scripts/assets. OpenGraph metadata по умолчанию generic и не
  раскрывает Space description;
- invalid, expired, exhausted и revoked selector имеют одинаковый публичный
  ответ. Preview DTO versioned/bounded, а selector в operational logs заменён
  HMAC-ref. Preview и join получают отдельные rate limits; expiry и use count
  обязательно bounded, unlimited/persistent link в первом contract отсутствует.
  Используется существующий `PermCreateInvite`, новый permission bit не
  вводится, а pre-release cutover удаляет это право из новых и уже сохранённых
  development default-role templates/rows;
- browser не получает account session, recovery flow, identity keys, messages
  или IPC. Красивый полноэкранный Veil Link portal — только invitation ceremony,
  а не crypto proof, `Verified` state или браузерный Veil client. Keyboard path,
  visible focus, semantic headings/status, live announcement ошибок и reduced
  motion входят в его acceptance matrix;
- authoritative parser живёт в native Rust. HTTPS authority задаёт заявленный
  origin; custom `veil:` payload считается недоверенным транспортом и не может
  сам доказать origin. Locked app держит не более одного bounded pending link
  только в native volatile memory с коротким TTL и очисткой при replacement/
  cancel/timeout/process exit/successful consumption. Persistence возможна лишь
  через отдельно reviewed OS-sealed storage, но не plaintext config и не
  renderer state. Renderer получает только canonical origin, short selector
  reference, TTL и независимый random process-local flow nonce. Он не
  является selector/secret и нужен лишь для атомарной привязки preview,
  cancel и join к точному pending Link;
- после unlock link никогда автоматически не выбирает account, не переключает
  Node и не вступает в Space. При отсутствии аккаунта сначала выполняется
  обычный create/restore/auth на exact origin; Veil Link не является enrollment
  либо auth credential, а closed registration честно блокирует join. Отдельный
  Node enrollment/bootstrap требует собственного review;
- state machine фиксирована как `parse → unlock → exact-origin account →
  create/restore/auth if allowed → signed native preview request → explicit Join
  → atomic membership → roster quarantine → ready`;
- native flow повторно получает свежий preview через signed native request,
  привязанный к exact authenticated TLS origin/generation, показывает выбранную
  local identity, join/history conditions и требует явный Join. При другом
  origin нужен явный account/Node flow без ослабления TLS; redirects запрещены,
  а изменение origin/account/session generation инвалидирует незавершённый flow;
- membership публикуется только после атомарного authoritative join. Room hint
  является лишь навигацией после отдельной ACL-проверки; link даёт только
  обычную authoritative default membership role, не обходит Room policy и не
  выдаёт elevated role либо прошлые ключи. Сам link не переопределяет отдельно
  принятую history policy и не даёт доступ к Restricted Room. Отправка остаётся
  quarantined, пока exact roster и Sender-Key distribution не готовы;
- revoke/revoke-all, bounded lifecycle audit, authoritative ban и admission
  throttling защищают Space от raid и rotation DoS. Ban проверяется в той же
  транзакции, что expiry/use count/membership insert; отклонённый banned account
  не расходует use, не меняет membership/roster и не запускает rotation. Удаление
  или ban участника никогда не задерживается ради batching.

Первый 4E contract реализует `Veil Link(type=space)` с bounded immediate join.
Addressed Circle invite, request-to-join, Person Introduction, guest/role-bearing/
private-Room link, unlimited link и Node bootstrap являются отдельными capability
types/modes и не добавляются без собственного review.

### Deliverable: responsive contract и completion evidence

- Desktop реализует shell выше на существующих островах; новый широкий global
  rail или пятый Identity island не добавляются.
- Mobile contract: корневые Home и единый список Circles/Spaces; Direct находится
  внутри Home, Circle открывается сразу в chat, Space → Rooms → Room. Members и
  Identity являются modal bottom sheets со скрытием фона из accessibility tree,
  initial focus и возвратом к точному trigger. Android Back закрывает sheet,
  затем возвращает к Rooms или списку Circles/Spaces. Пустая Calls tab не
  появляется до рабочего Phase 7 runtime.
- Реализация mobile runtime остаётся в 5A/5B. Phase 4E фиксирует общий
  navigation/deep-link contract и выполняет физическую desktop↔desktop matrix;
  desktop↔Android становится evidence 5B/release gate.
- Тесты покрывают route/focus/reduced-motion, stale completion/access
  invalidation, long text/pseudo-locale, atomic initial Circle roster, create/
  join/leave/kick/role/overwrite/device revoke/offline reconnect, invite
  entropy/hash/one-time reveal, expiry/max-use race, revoke/revoke-all, rate
  limits, ban/rejoin/unban, generic public errors/headers, volatile pending-link
  lifetime, lock/account/origin transitions и отсутствие raw token в
  logs/referrer.

Не входят в 4E: browser messenger, новый crypto mode, Circle → Space migration,
posts/comments/polls/community runtime, звонки, production Android messaging,
полный product/download site и полная локализация. Эти границы не мешают их
будущей реализации, а не дают текущей фазе снова стать бесконечной.

Критерий выхода: пользователь без документации отличает Home, Direct, Circle,
Space, Room и Veil Node; создаёт Circle/Space из одного места и проходит Veil
Link от public preview до явного authenticated join. Permission/device changes
совпадают с exact roster и Sender-Key состоянием, profile metadata не участвует
в trust/ACL/rotation, silent plaintext fallback отсутствует. Component,
protocol/security, Docker, visual/a11y, Windows native и ручная физическая
desktop↔desktop матрицы зелёные; полный installer собирается на completion gate,
а не после каждого малого UI-checkpoint.

---

## Phase 5 — Android

**Текущее состояние:** Android уже не является изолированным visual prototype.
React Native shell подключён к fail-closed `VeilMobileRuntime` на Rust/UniFFI;
identity хранится через Android Keystore, account/runtime state — в SQLCipher,
а Node Access Pass, authenticated WebSocket, own prekeys, Direct directory,
history-to-live handoff, message projection и idempotent Direct text send/outbox
принадлежат native boundary. Это всё ещё закрытый Direct Preview: ACK deadline,
polished reconnect и подписанный standalone tester APK пока не готовы.

### Peer-prekey checkpoint 2026-07-19

Pause checkpoint 2026-07-18 завершён двумя отдельными проверенными коммитами.
Статусы ниже разделяют опубликованный код и ещё не реализованный scope; dirty
worktree после публикации отсутствует.

**Опубликовано и проверено в `codex/mobile-direct-preview`:**

- authoritative head этого peer-prekey checkpoint — `f21c9c0`
  (`feat(android): add explicit peer prekey transport`), его обязательный Rust
  predecessor — `029d1e3`
  (`feat(mobile): guard peer prekey capability in Rust`); `master` этими
  checkpoint не изменялся;
- mobile-only registration по Node Access Pass, Keystore-wrapped identity,
  native SQLCipher/session runtime и exact origin/account binding;
- own-prekey bootstrap, authenticated Direct directory, immutable history,
  bounded gap-free history-to-live handoff, continuous FIFO replay и read-only
  projection только явно выбранного Direct;
- native advisory send readiness повторно проверяет live ratchet, lease/epoch,
  durable scope, identity pin, quarantine/history, storage и connection state;
- Rust one-shot peer-prekey capability допускает максимум одну released
  signature, повторяет authoritative guards до/после signing и при install,
  сохраняет exact lease/request binding, response limits и zeroization;
- Android `establishDirectSession` привязан к exact lifecycle epoch и Direct
  generation: prepare → одна signature → один bounded GET → install. Background,
  reconnect и late callback отзывают lease и очищают body; OkHttp network guard
  блокирует status-driven 503/421 follow-up до второго signed wire exchange;
- exact `c9f2d06` прошёл Go, Coverage, Rust и Mobile CI. Security workflow красный
  только на прежнем Cargo Audit baseline (те же 7 advisories и 19 разрешённых
  warnings, без новой регрессии). CI debug APK является build evidence, а не
  подписанным tester release и не physical-device evidence.

**Локальная completion evidence для `029d1e3` + `f21c9c0`:**

- `cargo fmt --all -- --check`, workspace clippy с `-D warnings`, полный
  `cargo test --workspace --all-targets` и отдельный `veil-ffi` summary 65/65;
- retained-outstanding/Ready, post-sign lease replacement, install/background,
  reconnect/late-body, exactly-one signature/GET и prepare/sign/create-call
  cleanup покрыты deterministic adversarial tests;
- Android native libraries воспроизводимо пересобраны для `arm64-v8a` и
  `x86_64`; `verifyVeilRustLibraries`, JVM 142/142, `lintDebug` с 0 errors и
  `assembleDebug` для обеих ABI прошли без исключения `.so` preflight;
- UniFFI regeneration byte-for-byte стабильна; contract version 29 и 68/68
  checksums совпали для host DLL, обеих source `.so`, merged и stripped
  intermediates;
- ESLint, TypeScript и Jest 68/68 прошли после frozen pnpm install. Windows
  virtual-store path policy не меняет dependency lock и Jest больше не зависит
  от полного имени служебного `.pnpm` каталога;
- два независимых exact-diff review после исправления OkHttp follow-up вернули
  `P0/P1/P2: none`. Debug APK остаётся build evidence с debug key, а не tester
  release и не physical-device evidence.

### Idempotent Direct send/outbox checkpoint 2026-07-19

Shared protocol/server/client core и Android send slice опубликованы четырьмя
раздельными checkpoint. `master` не изменялся.

**Опубликовано в `codex/mobile-direct-preview`:**

- `6e128b3` (`feat(protocol): make Direct sends idempotent`) добавляет
  `client_message_id` в Send/ACK/Error и серверную unique scope + exact request
  digest. Повтор тех же bytes/ID возвращает прежние message ID/time без второго
  insert или fan-out; конфликт reuse отклоняется;
- `6a979ee` (`feat(client): persist exact Direct outbox`) атомарно сохраняет
  advanced ratchet, local Sending row и exact serialized ciphertext outbox в
  одной SQLCipher-транзакции. ACK/definite rejection reconcile-ятся атомарно,
  retryable transport loss сохраняет исходные bytes/ID;
- `9b11100` (`feat(ffi): bridge durable Direct send`) держит replay cursor только
  в Rust, повторяет lock/authority guards в порядке `direct_sync → binding →
  client` и не переносит message ID, sequence, ciphertext или timestamp через
  FFI. Live quiescence больше не открывает Ready до bounded replay, который
  подтвердил конец durable outbox;
- `5d62f95` (`feat(android): enable native Direct text send`) добавляет один
  lifecycle/generation-bound user intent, atomic native enqueue, ровно один
  destructive peer-prekey GET и ровно один post-install retry. Kotlin plaintext
  buffer стирается на accepted/rejected/revoke/background/late callback;
- `AcceptedForReplay` означает успешное durable принятие ровно один раз, после
  чего старая generation и binding немедленно отзываются. Отдельно исправлена и
  listener-тестом закреплена публикация fail-closed snapshot после revoke;
- React Native composer не создаёт optimistic UUID/row/time и не получает
  protocol identifiers. Он очищает draft только после native accepted и затем
  перечитывает authoritative SQLCipher projection; stale generation и второй
  tap ничего не публикуют.

**Completion evidence:**

- полный `cargo test --workspace --all-targets`: 505 passed, 0 failed,
  12 ignored; `veil-ffi` 70/70; workspace clippy с `-D warnings`, fmt и
  `git diff --check` зелёные;
- полный Go suite и race-набор `chat/db/gateway` прошли для protocol/server
  checkpoint; свежая PostgreSQL migration/idempotency/concurrency матрица
  проверена до публикации core;
- native libraries воспроизводимо пересобраны для `arm64-v8a` и `x86_64`;
  `verifyVeilRustLibraries`, полный JVM 151/151, `lintDebug` с 0 errors и
  `assembleDebug` прошли без исключения `.so` preflight;
- повторная UniFFI generation byte-for-byte стабильна, SHA-256 generated Kotlin
  `A010945BFA506516D1F47CB36EACE3D6F48D8AF0ED59AD0C44B530204908053A`;
- TypeScript, ESLint и Jest 80/80 зелёные. Adversarial tests покрывают bounded
  outbox turns, storage/transport revoke, prekey one-shot, duplicate tap,
  plaintext bounds/wipe, contentRevision races и отсутствие optimistic row;
- независимый exact-diff review обнаружил и помог закрыть один Android P1
  (непубликуемый revoke snapshot); повторный review вернул `P0/P1/P2: none`.

Debug APK остаётся только build evidence с debug key. Он не является
подписанным tester release и не заменяет physical-device evidence.

**На момент этого checkpoint не было реализовано и не считалось готовым:**

- monotonic ACK deadline для live transport correlation;
- typed разделение ordinary transport loss, retryable connect failure,
  protocol/auth anomaly и storage uncertainty. Строковые ошибки намеренно не
  используются для решения о retry;
- transient-only reconnect с full-jitter exponential backoff, reset только
  после полного Ready + outbox barrier, lifecycle cancellation и проверкой
  неизменного account ID;
- process-death origin recovery и airplane-mode/reconnect physical matrix;
- push publication, Circle, Space/Rooms, attachments, multi-device
  enrollment/revoke;
- release signing, standalone tester APK, чистая установка и physical-device
  matrix. Ни текущий CI APK, ни локальный debug APK не являются tester release.

**Следующий порядок на момент этого checkpoint:**

1. Ввести typed connect/live/outbox stop taxonomy и native monotonic ACK
   deadline, не retry-я protocol/storage/security failures.
2. Добавить Kotlin-owned single reconnect plan с full jitter, exact lifecycle /
   session/origin/account guards и отменой при background/lock/manual connect.
3. Сохранять выбранный canonical origin native-side для безопасного
   process-death recovery без Node Access Pass replay.
4. Пройти airplane-mode/process-death/physical matrix и только после этого
   собрать подписанный standalone tester APK.

### Typed Direct terminal/ACK checkpoint 2026-07-19

Typed live/connect/outbox taxonomy и monotonic ACK deadline опубликованы двумя
раздельными checkpoint в `codex/mobile-direct-preview`; `master` не изменялся.

**Опубликовано и проверено:**

- `cbecd94` (`feat(client): harden Direct terminal reconciliation`) вводит
  source-typed connect/WebSocket/send terminal causes и положительный retry
  allowlist. Protocol/auth/security anomaly и storage uncertainty никогда не
  становятся retryable по тексту ошибки; storage остаётся sticky fail-closed;
- каждый durable Direct sequence получает отдельный monotonic ACK deadline и
  конечный FIFO snapshot. Более поздние события не расширяют grace window,
  staggered deadlines не делят один watermark, а ACK, уже попавший в очередь к
  первому наблюдению expiry, получает ограниченный post-poll turn;
- ACK/Error correlation сначала строит взаимоисключающий typed reconciliation
  plan. Repeated durable receipt не может по старому `ref_seq` подтвердить
  mutation, sender-key или новый command; mutation ACK обязан совпасть с exact
  target message ID;
- read-only SQLCipher receipt validation различает unknown/conflicting/opposite
  protocol result и реальную storage uncertainty. UUID из другого
  origin/user/device scope не alias-ится с текущим durable receipt;
- ACK timestamp обязан давать положительный millisecond value, correlated Error
  принимает только HTTP-like `400..=599`, а retry допускает только exact `429`,
  exact unauthenticated `401` и `500..=599`;
- `ad0713e` (`feat(android): classify accepted invalid Direct sessions`) добавляет
  `AcceptedSessionInvalid` во FFI/UniFFI/Android contract. Intent уже принадлежит
  SQLCipher и завершается как accepted ровно один раз, но Kotlin отзывает lease,
  binding и public generation и не выдаёт automatic reconnect permission.

**Completion evidence:**

- `cargo test --workspace --all-targets` завершён без ошибок; отдельно
  `veil-client` 165 passed / 11 ignored, `veil-ffi` 75/75 и `veil-store` 79/79;
  workspace clippy с `-D warnings`, `cargo fmt --check` и `git diff --check`
  зелёные;
- UniFFI и Android native libraries дважды воспроизводимо пересобраны для
  `arm64-v8a` и `x86_64`. SHA-256 generated Kotlin:
  `2C18588C73F907E9AB7525BE9ABB8D8C6EFA990AD804DC520D115904B016F995`;
- `verifyVeilRustLibraries`, полный JVM suite 152/152, `lintDebug` и
  `assembleDebug` прошли без исключения `.so` preflight; собранный debug APK
  содержит обе ABI;
- TypeScript, ESLint и Jest 80/80 зелёные. Независимые ACK snapshot и
  FFI/Android exact-diff аудиты после исправлений не нашли P0/P1/P2.

Локальный debug APK остаётся только build evidence с debug key. Он не является
подписанным tester release и не заменяет physical-device evidence.

**Следующий порядок:**

1. Добавить Kotlin-owned ровно один reconnect plan с full-jitter exponential
   backoff, exact lifecycle/session/origin/account guards и отменой при
   background, lock, manual connect и manual disconnect.
2. Сбрасывать backoff только после полного Ready + durable outbox barrier;
   планировать reconnect только для typed `Transport`/`AckDeadline`, никогда для
   `AcceptedSessionInvalid`, protocol/storage/security failure.
3. Сохранить выбранный canonical origin native-side для process-death recovery
   без хранения или повторного использования Node Access Pass.
4. Пройти airplane-mode/process-death/physical matrix и только после этого
   собрать подписанный standalone tester APK.

Ранее обязательные исправления проекта — текущий статус:

- Закрыто: TypeScript использует совместимые `module: esnext` и
  `moduleResolution: bundler`.
- Закрыто: ESLint/Jest dependencies и unit/component/runtime suites подключены.
- Закрыто для production boundary: raw JS crypto mock/sign/AEAD surface удалён;
  отсутствие native module приводит к fail-closed ошибке.
- Решение сохранено: React Navigation + StyleSheet остаются оболочкой; миграция
  на NativeWind/Expo Router без измеримой пользы не планируется.

### Phase 5A — Android foundation

**Foundation checkpoint 2026-07-18: в работе.** Android project теперь
versioned; Rust/UniFFI воспроизводимо собирается для `arm64-v8a` и `x86_64`.
Удалён runtime crypto mock и raw sign/AEAD JS surface, release больше не может
подписываться debug key. Recovery phrase хранится через Android Keystore-wrapped
AES-GCM vault, backup отключён, secret screens используют `FLAG_SECURE`, copy в
clipboard удалён и добавлено подтверждение слов. Состояния local identity и
native failure разделены. Это закрывает первый пункт и часть пунктов 3–5 ниже,
а SQLCipher, lifecycle lock policy и authenticated mobile runtime теперь
подключены. Standalone signing/physical matrix и end-to-end reconnect gate
остаются открыты и не позволяют считать 5A завершённой.

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
6. Реальный endpoint config, certificate validation, signed REST/WS, offline
   outbox и атомарные crypto+message SQLCipher transactions подключены;
   transient-only reconnect и process-death recovery остаются открыты.
7. Enrollment второго устройства и revoke flow как prerequisite для групп,
   server channels и MLS.
8. Android Back закрывает dialog/sheet, затем возвращает к Rooms/Spaces либо
   предыдущему native route, и только потом покидает экран.
9. Профилировать blur, HebrewRain и текущие четыре одновременно смонтированные
   pager page на слабых устройствах; целевой route не держит невидимые тяжёлые
   экраны без необходимости и respect reduced motion/battery saver.
10. Перевести prototype на общий 4E navigation contract: корневые Home и единый
    список Circles/Spaces, Direct внутри Home, Circle сразу в chat, Space →
    Rooms → Room, Members и Identity как bottom sheets. Это меняет presentation/
    navigation, но не даёт JS доступ к crypto state.

Результат 5A: подписанный internal APK запускается на чистом устройстве,
создаёт/восстанавливает identity, переживает restart, безопасно lock/unlock и
соединяется с тестовым gateway без доступа JS к секретному состоянию.

### Phase 5B — Android messaging

**Direct text checkpoint 2026-07-19: частично готов.** Настоящие Direct list,
authenticated history, bounded live receive, native projection, X3DH one-shot
peer-prekey и idempotent SQLCipher-owned send/outbox опубликованы в цепочке
`029d1e3`…`5d62f95`. ACK deadline, reconnect/process-death matrix, private
groups и остальные пункты 5B не готовы.

1. Сначала один честный Desktop ↔ Android DM: X3DH/Double Ratchet, history sync,
   ack/outbox, reconnect, airplane mode и process death.
2. Реальные DM list/chat, затем private groups на Sender Keys.
3. Circles и Space/Rooms подключать только после Phase 4E product contract,
   Phase 4C exact-device roster и тех же fail-closed crypto indicators.
4. Generic notification «Новое сообщение» + foreground sync. Encrypted preview
   включать только после полного `K_push` lifecycle.
5. Origin-scoped Veil Link принимает Android только через native parser,
   unlock/account confirmation и authoritative join; browser preview не
   передаёт Android account session.
6. Затем attachments, search, settings/Appearance и Space management.
7. Device/instrumentation tests, signed AAB и закрытый beta rollout.

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

Продуктовая поверхность: Direct calls, calls внутри Circle и Voice Rooms внутри
Space. Phase 4E резервирует расширяемый Room type/navigation contract, но не
показывает неработающую Voice Room как доступную функцию. Реальный runtime,
permissions и media indicators появляются только в этой фазе.

E2EE через LiveKit insertable streams, ключи деривируются из MLS exporter secret
(или sender-key chain) с меткой `"livekit-call-v1"`.

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

### Автономный LAN и air-gapped deployment

Автономность — обязательное свойство релиза, а не best-effort режим. Она не
создаёт ещё одну вложенную фазу и проверяется тремя прямыми deliverables:

Текущий development release этот gate ещё не проходит: NSIS не выбирает
offline WebView2 mode, Compose при cold install рассчитывает на заранее
загруженные образы или registry, а физическая WAN-off matrix не выполнена.
Успешная работа уже установленного стенда не заменяет clean-room evidence.

1. **Offline runtime:** уже установленный клиент холодно стартует и после
   restart подключается к локальному gateway без WAN. Auth, SQLCipher history,
   DM/groups/server channels, локальные attachments и администрирование не
   требуют cloud control plane. Push, updater и внешний relay деградируют явно.
2. **Offline installation:** подписанные клиентские пакеты и versioned Veil Node
   bundle устанавливаются из локального носителя. Windows bundle включает
   offline WebView2 installer; Linux выпускается как AppImage плюс `.deb` и
   `.rpm`, но совместимость обещается только для проверенных distro/version/arch,
   включая выбранные российские дистрибутивы. macOS получает заранее подписанный
   и notarized DMG со stapled ticket и WAN-off Gatekeeper smoke; новая
   notarization полностью без связи с Apple невозможна. Android после Phase 5
   получает подписанный standalone APK для local/managed install наряду с AAB
   для store distribution; iOS air-gap sideload не обещается.
3. **Offline release factory:** target-specific reproducible runners используют
   vendored Cargo crates, зафиксированный pnpm store/Go modules, toolchains и OS
   SDK. Windows/MSI строится на Windows runner, macOS — на macOS runner,
   Linux targets — на зафиксированных oldest-supported контейнерах/VM. Обещания
   «одна машина собирает любую ОС» нет.

Veil Node air-gap bundle содержит pinned multi-arch OCI images gateway,
PostgreSQL, ntfy и будущих LiveKit/coturn, Compose/manifests, migration,
backup/restore, checksums/signatures, локальную документацию и install/upgrade
scripts без `pull`. Для поддерживаемых targets предоставляется либо проверенный
offline OCI-runtime package set, либо готовый appliance/VM image; наличие
интернета во время первичной установки не предполагается.

Локальный bootstrap обязан решить DNS, TLS и время без ослабления проверок:
split-horizon DNS сохраняет exact origin, offline CA/certificate enrollment
требует явной fingerprint verification, а локальный time source предотвращает
поломку timestamp-bound auth и certificate lifecycle. Запрещены auto-trust
self-signed certificates, `--insecure`, HTTP fallback и смена identity namespace.

Критерий выхода: на чистых образах каждого supported target физически отключён
WAN; с USB/локального share разворачиваются Veil Node и клиенты, создаётся новый
account, проходят message/file/local-call, restart, backup/restore и signed
offline update. Updater хранит monotonic version floor и отклоняет downgrade.
Rollback допускается только отдельным подписанным recovery manifest с явно
разрешённой target version, schema compatibility и проверенным backup/restore
path. Все сетевые обращения наружу либо отсутствуют, либо показываются как
необязательная недоступная функция.

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
- origin-hosted Veil Link portal из Phase 4E использует канонический сайт только
  как download/documentation fallback. Он остаётся страницей целевого Node,
  работает в LAN без WAN и не проксирует invite secret через центральный сайт;
- браузерного клиента Veil не будет. Помимо статических product/docs/download
  страниц и локальной gateway landing разрешены только два узких capability-
  oriented web flow: one-time Share Viewer с собственным ограниченным threat
  model и unauthenticated allowlisted Veil Link preview. Ни один из них не
  становится web messenger и не получает account identity/session, recovery
  flow или keys.

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
  `Phaseprint`; продуктовые термины `Home`, `Direct`, `Circle`, `Space`, `Room`,
  `Veil Link` и `Veil Node` также получают стабильные semantic keys. Перевод не
  имеет права повышать заявленный trust state либо смешивать Space и Node.

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
- P4E+: явная Circle → Space migration и будущие Community/Board/Stage модели с
  posts, comments, reactions и polls проектируются после закрытия 4E; они не
  могут молча менять history, membership, crypto mode или notification privacy
- P5: React Navigation + PagerView остаются текущей мобильной оболочкой;
  переход на другой router допустим только при конкретной пользе для общего
  Home/Circle/Space/Room contract
- P5: UnifiedPush-only либо опциональный FCM wake-up с generic encrypted payload?
- P6: per-device credential — стабильный opaque device ID; человекочитаемый
  label не входит в криптографическую identity и может меняться
- P6: окончательный MLS threshold определяется benchmark/ADR, а не числом из старого roadmap
- P7: свой coturn или внешний? → свой в compose, ради приватности
- P8: code signing certs (macOS/Windows) → нужны до public beta, отдельный бюджетный вопрос
- P8: Play Store internal/closed beta либо параллельный direct APK/F-Droid канал
