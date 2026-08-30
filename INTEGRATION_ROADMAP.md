# Дорожная карта Veil

> **Clean Slate v0.3 — начат 2026-08-30.** Принят
> [`ADR-0004`](docs/adr/0004-clean-slate-v0.3-and-open-source-crypto.md): история
> сообщений и старое crypto-state не являются целью совместимости; identity,
> device trust и Node configuration сохраняются только через явно проверенные
> инварианты. Группы переходят на MLS/OpenMLS после persistence/rollback/
> offline/Android gates. Direct v2 остаётся рабочим до отдельного двухстороннего
> MLS решения. Новые security-компоненты по умолчанию выбираются из
> поддерживаемых open-source реализаций открытых стандартов, но проходят
> собственную проверку application boundaries.
>
> Текущий шаг: удалить низкорисковый runtime legacy (PIN 4-5, Android vault
> migration, retired `/ws`), ввести явные clean-slate version barriers и
> зафиксировать тестами отсутствие downgrade. Следующий шаг: обновление и
> hardening изолированного `veil-mls`; живой MLS runtime пока не включается.
>
> **Dependency checkpoint 2026-08-30:** patched the actionable desktop/mobile
> `nanoid` and `js-yaml` advisories with narrow pnpm overrides. Mobile CI keeps
> only the two exact, time-bounded `image-size` build-tool exceptions documented
> in `docs/reviews/mobile-image-size-audit-exception-2026-08-30.md`; every other
> low-or-higher pnpm advisory remains blocking. Frozen-lockfile validation,
> desktop audit, mobile audit, mobile TypeScript, ESLint, and all 233 mobile
> tests pass locally. The next Clean Slate work item is the explicit persisted
> messaging-state version/epoch barrier, followed by `veil-mls` persistence and
> rollback hardening before any MLS runtime promotion.
>
> **Checkpoint 2026-08-30:** ADR и open-source policy зафиксированы; desktop
> PIN 4–5, Android SharedPreferences vault migration и зарегистрированный
> `/ws` tombstone удалены. Desktop TypeScript boundary проходит локально.
> Rust/Go/Android проверки должны пройти в CI, так как локальный Windows host
> не предоставляет эти toolchains. Messaging-state epoch и OpenMLS hardening —
> следующий незавершённый шаг; Sender Keys и Direct не удалялись.

> Актуально на 2026-08-30. Это основной продуктовый и интеграционный план.
> [`ROADMAP.md`](ROADMAP.md) сохранён как исторический security/infra backlog;
> при расхождении приоритетов главным считается этот документ.

Текущий переносимый beta-checkpoint, включая локальные UI-изменения,
экспериментальный `/v3/events`, macOS x86_64 build evidence, точные результаты
проверок и известные blockers, опубликован в
[`docs/reviews/beta-integration-macos-2026-08-04.md`](docs/reviews/beta-integration-macos-2026-08-04.md).
Успешная локальная сборка неподписанного DMG не закрывает Phase 8, а наличие
endpoint/UI scaffolding не закрывает Android parity или hostile-Node gate 5S.

Итог security-hardening диапазона `b8ed439..92fc1c3`, точные проверки и
оставшиеся release blockers зафиксированы в
[`docs/reviews/security-hardening-audit-handoff-2026-08-05.md`](docs/reviews/security-hardening-audit-handoff-2026-08-05.md).
На `92fc1c3` полный GitHub CI и beta artifact matrix зелёные; это инженерное
свидетельство, а не замена независимому аудиту, подписи релиза или physical gate.

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
6. До public beta закрыть Phase 4F: отделить полномочия Node operator от Space
   moderation, добавить транзакционный audit и встроенный report/case lifecycle.
7. Secure Share вести как отдельную Phase 4G: сначала reviewed text/small-payload
   capability, затем streaming large-file flow на фундаменте Phase 3B.
8. Продолжить Android Direct Preview: foundation/runtime 5A, receive/read,
   one-shot peer-prekey, shared idempotent send/outbox, typed ACK deadline,
   transient reconnect и automated canonical-origin process-death recovery уже
   реализованы. Ограниченный Samsung S23 smoke подтверждает Pass registration,
   public-WebPKI transport, empty Direct и same-account force-stop reopen, но
   полный Desktop ↔ Android E2EE/send/ACK/outbox/reconnect/airplane/background/
   process-death gate и connected recovery/capture matrix остаются открыты.
   Полный workspace, UniFFI/Kotlin bindings, обе native ABI и debug APK теперь
   собираются и проверяются Mobile CI. Короткоживущий `veil-mobile-debug-ci`
   пригоден для диагностики, но стабильный подписанный tester APK ещё не
   произведён и не проверен.
   Точный checkpoint приведён в Phase 5.
   Следующий функциональный parity-срез — native contacts → identity check →
   friend request → create Direct. В beta baseline `f6dbf5a` уже есть UI,
   FFI/Kotlin и request scaffolding, но это не рабочий flow: create-Direct route,
   identity header и friend-request REST contract ещё не сведены в один
   production flow. Текущий Android
   по-прежнему надёжно обслуживает только существующий authenticated Direct
   directory. Контракт, запрещающий renderer-only или cross-origin fallback,
   зафиксирован в
   [`android-native-contacts-direct-initiation-contract.md`](docs/reviews/android-native-contacts-direct-initiation-contract.md).
9. Реализация security baseline 5S существенно закрыта: production переведён
   на origin/account/device-bound WS v3 и REST v2 без legacy network fallback;
   hostile two-Node, Direct v2, transparency/witness/gossip и membership-epoch
   contracts покрыты точными fixtures и CI. До release exit остаются независимый
   аудит, deployable independent witnesses, Direct-vs-`libsignal` ADR и physical
   Android fingerprint/QR/key-change matrix. Поэтому stable/critical-use claims
   по-прежнему заблокированы.
10. Затем довести MLS runtime, звонки и release polish.

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
| 4F | Node Administration, Moderation & Reports | запланировано: Space moderation существует, Node console/report queue отсутствуют |
| 4G | Secure Share for guests | prototype foundation существует; production gateway/viewer/large-file lifecycle отсутствуют |
| 5A | Android foundation | core runtime, TLS, atomic vault, lifecycle/Pass authority, native recovery и debug Ready-capture checkpoints опубликованы; полный workspace, UniFFI/Kotlin bindings, `arm64-v8a`/`x86_64` payloads и short-lived debug APK зелёные в Mobile CI; stable signed tester APK и deferred A04/A05/recovery/vault/capture physical matrix открыты |
| 5B | Android messaging | automated receive/read, one-shot peer-prekey, idempotent native send/outbox, typed ACK, transient reconnect и true-empty Ready опубликованы; contacts/create-Direct UI и native request scaffolding добавлены, но route/header/friend-request/UniFFI contracts не состыкованы; полная Desktop ↔ Android E2EE/airplane/background/process-death matrix открыта |
| 5C | Secure QR device linking / multi-device | отдельный blocking gate не начат: second-device enrollment, SAS approval, atomic activation, revoke и hostile-relay matrix обязательны до корректного multi-device |
| 5S | Direct protocol assurance & hostile Node | production WS v3/REST v2 cutover выполнен, legacy `/ws`/REST v1 fail closed, cross-Node credential-scope P1 и hostile two-Node relay matrix закрыты; Direct v2, transparency/witness/gossip, membership epochs и Sender-Key v6 реализованы и покрыты frozen vectors/CI; release exit открыт до Direct-vs-`libsignal` ADR, independently operated witnesses, physical Android trust/QR matrix и независимого аудита |
| 6 | OpenMLS | фундамент готов, runtime-ветвление выключено |
| 7 | LiveKit звонки | не начато |
| 8 | Полировка, релиз | частично: полный CI и beta artifact matrix зелёные на `92fc1c3`, short-lived debug APK и unsigned desktop artifacts доступны; stable signing/notarization, signed tester APK, physical matrices и public release gate отсутствуют |

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
| **Secure Share** *(reserved planned term)* | настраиваемая E2EE-ссылка для текста/файлов получателю без аккаунта | несовместимые prototype crypto/schema/viewer pieces; production flow отсутствует |
| **Community** *(future)* | публикационное совместное пространство с постами, комментариями, реакциями и опросами | отдельный будущий product/schema/privacy/security contract; runtime отсутствует |

`Home`, `Direct`, `Circle`, `Space`, `Room`, `Veil Link` и `Veil Node` являются
текущим продуктовым языком. `Secure Share` зарезервирован только для Phase 4G и
не означает доступную функцию. Внутренние `dm/group/server/channel` в PostgreSQL, REST,
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
- Desktop context menu на mobile становится long-press + modal bottom sheet/
  action sheet с теми же capability checks, destructive confirmation и точным
  возвратом focus. Ни одно действие не может зависеть только от hover/right-click.
- Реальный mobile roster переиспользует общий `UserAvatar`/Phaseprint и
  Identity Island. Role и nickname остаются только Context: они не меняют
  identity proof, trust, ACL или ключи. До authoritative roster локальный
  дизайн-макет не выдаёт initials/role/presence за данные Node.
- Mobile не копирует desktop multi-island layout пиксельно, но обязан оставаться
  тем же Veil Design System: общие palette/type/radius/spacing/motion tokens,
  PhaseShift/Phaseprint, термины, trust/crypto indicators, unread semantics и
  public failure states. Desktop раскладывает контексты рядом, mobile открывает
  те же контексты последовательным native stack; различие компоновки не может
  менять capability, security state или смысл действия.
- Mobile Appearance использует те же versioned theme IDs/tokens, но уважает
  Android font/display scale вместо копирования desktop UI-scale. Настройки
  различают реальные `switch`, enum selector/action sheet, slider, OS action и
  read-only status; неработающие строки не выглядят интерактивными. Wallpaper и
  avatar customization появляются только вместе с native sanitize/cache/size
  boundary и никогда не загружаются в небезопасный JS/WebView path.
- Корневой mobile shell ограничен тремя понятными направлениями: `Home`
  (contacts/requests/Direct), `Spaces` (единый список Circles и Spaces) и
  `Updates` (упоминания, ответы, приглашения и security events). Settings
  открывается через постоянный account control, а не смешивается с Veil Node,
  Space или Room. До наличия настоящей native projection направление не
  показывается как рабочее. Debug/visual build может содержать отдельный явно
  подписанный `DESIGN PREVIEW` с локальными Circle/Space/Room/Voice Room fixtures
  для утверждения IA, но он не смешивается с Node projection, не разрешает
  create/join/send/call/role actions и не делает runtime/security claims.
  Voice Room fixture остаётся только схемой интерфейса до Phase 7.
- Слово `Server` не используется как синоним Discord-like контейнера: такой
  контейнер называется `Space`, а `Veil Node` остаётся origin/account boundary и
  показывается в Settings/connection context. Если появится multi-origin account
  switcher, он не смешивается со списком Spaces и всегда раскрывает смену identity/
  trust scope до перехода.
- Переходы фиксированы: `Home → Direct`, `Spaces → Circle`, `Spaces → Space →
  Rooms → Room`; Circle не получает искусственный список Rooms. Members,
  Identity и context details открываются sheet-ами из явной кнопки в header;
  swipe может быть shortcut, но не единственным доступным способом.
- Unread является точкой, а mention/reply — отдельным `@N` count. Сигнал
  агрегируется без потери пути: root → exact Circle/Space → exact Room → message.
  Открытие списка Space не помечает Room прочитанной; read cursor продвигается
  только после authoritative projection и фактического показа сообщения. Updates
  jump повторно проверяет origin/account/membership/Room ACL и при stale access
  fail closed возвращает в свежий допустимый контекст.
- Push до полного `K_push` lifecycle остаётся generic wake-up без имени, текста,
  Space/Room или mention preview. После unlock клиент дедуплицирует событие по
  origin-scoped message identity и вычисляет badges из проверенного локального
  состояния, а не доверяет server-provided count. Multi-device read-state merge
  требует отдельного versioned cursor contract и не угадывается по delivery ACK.
- В authenticated content не используется постоянный полноэкранный ambient glow.
  Фирменный свет остаётся дозированным в onboarding, empty/celebration state и
  focused action; blur применяется к компактному navigation chrome/sheet, а не
  ко всему message surface. Reduced motion и battery saver отключают декоративную
  анимацию без потери hierarchy/status.
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

## Phase 4F — Node Administration, Moderation & Reports

**Статус 2026-07-15: запланировано.** Полноценной Node-админки и встроенной
системы жалоб сейчас нет. Реализованы роли/ACL, kick, authoritative Space ban/
unban и Veil Links внутри отдельного Space; `veil-admin` умеет только создавать
Node Access Pass. Текущий пользовательский abuse flow — ручное обращение на
`abuse@erez.pro`.

Полный product/security contract находится в
[`docs/product/node-administration-and-reports.md`](docs/product/node-administration-and-reports.md).
Phase 4F разделяет две независимые authority:

- Space owner/moderator управляет только своим Space;
- Node operator управляет одним self-hosted инстансом, admission, account
  availability, quotas и abuse cases. Report schema не имеет key-material fields,
  а официальный клиент не читает/не экспортирует recovery/account/device/ratchet/
  attachment stores. Storage получает encrypted evidence package, а выбранный
  untrusted plaintext раскрывается только authorized moderation role. Existing
  TOFU/malicious-service limits сохраняются до transparency work.

### 4F.1 — private operator boundary и CLI

- Отдельная operator identity/authorization namespace, не обычный Veil account
  и не Space role.
- CLI-first управление через local root-owned boundary; удалённо — SSH/private
  management network. Public `/admin` с обычной account session не добавляется.
- Bounded list/inspect account/device state, lifecycle Node Access Pass и quota.
  Node-level account/device denial хранится отдельно от account-signed device
  binding и увеличивает monotonic authorization revision; REST остаётся stateless,
  а live session означает WebSocket connection.
- Высокорисковые действия требуют reason, expected revision и повторной
  авторизации; санкция и typed audit entry фиксируются атомарно.

### 4F.2 — Space moderation parity

- Desktop открывает kick/ban/unban делегированным ролям ровно по authoritative
  permissions, а не только owner UI condition.
- Добавляются warning/timeout/mute с bounded reason/expiry и понятным appeal
  path; Space ban остаётся отдельным от Node suspension.
- `Manage Messages` либо получает review и реальную серверную semantics для
  чужого сообщения, либо удаляется из UI до реализации. Нельзя показывать
  неработающее moderation permission.

### 4F.3 — reports и добровольное evidence disclosure

- In-app `Report` покрывает account/profile, Space/Room metadata, Veil Link,
  Secure Share, file и конкретное message reference.
- Жалоба имеет bounded category/comment, random receipt ID, deduplication и
  retention. Per-account/capability/IP limits ограничивают cost/queue growth;
  uniform response не перечисляет чужие аккаунты, receipt не раскрывает case/
  target data, attacker-selected content не отражается третьим лицам.
- E2EE plaintext/attachment передаётся модератору только после отдельного
  подтверждения точного выбранного evidence. История, recovery phrase,
  ratchet/file keys и unrelated context не прикладываются автоматически.
- Selective-disclosure evidence получает отдельный crypto review: reporter-
  supplied plaintext нельзя без доказательства называть verified authorship.

### 4F.4 — audit и private console

- Typed hash-linked operator journal хранит scoped immutable actor/action/target/
  case/reason, timestamp и commitment предыдущей записи. Tamper evidence против
  root/DB operator требует independently signed checkpoint с custody вне live
  Node/DB, append-only export, fork/rollback detection и verifier procedure. В
  journal нет username, public key, raw
  content, token, IP или arbitrary JSON; доступ к evidence также audit event.
- Case lifecycle revision-checked и идемпотентен при concurrent operators:
  `new -> triaged -> actioned | dismissed -> appealed? -> closed`.
- Private console начинается read-only dashboard и только затем получает узкие
  mutations. Operator authentication, short session, re-auth, CSRF/CSP и
  отсутствие browser-stored bearer являются blocking requirements.

Критерий выхода: Space moderator не может получить Node privileges; report schema
не имеет key fields и official evidence builder не читает/автоматически не
экспортирует protected key stores; storage получает encrypted evidence package,
а selected untrusted content доступен только authorized moderation role. TOFU/
malicious-service limits документированы. DB sanction + audit является
linearization point: после commit новая revision блокирует stale HTTP/WS auth,
а соединения закрываются идемпотентно в bounded deadline. Concurrent sanction/
case операции сохраняют audit chain и independently verified checkpoint, а
purge/backup/restore не воскресают истёкшее evidence. Integration/concurrency/
security/native UI/privacy gates зелёные. До
этого момента продукт честно описывает только Space administration и ручной
abuse contact.

---

## Phase 4G — Secure Share for guests

**Статус 2026-07-15: prototype foundation, production flow отсутствует.** В
репозитории есть legacy `shares` schema, small-payload crypto и экспериментальный
WASM viewer, но gateway не регистрирует share API, ожидаемый viewer bundle/API
не собирается, schema/protobuf/password formats не согласованы, а whole-buffer
JSON/WASM path непригоден для больших файлов.

Авторитетный planned contract находится в
[`docs/product/secure-share-for-guests.md`](docs/product/secure-share-for-guests.md).
Secure Share — узкая E2EE capability: зарегистрированный creator отправляет
текст/файлы получателю без Veil account. Это не browser messenger и не anonymous
account session.

Canonical v1 link имеет вид:

```text
https://node.example/s/v1/<public-selector>#k=<root-secret>
```

Selector только находит запись. 256-bit fragment secret не уходит в HTTP request;
domain-separated KDF с version/origin/selector context независимо выводит content,
redemption и report capability material. Node хранит только domain-separated
credential hashes и ciphertext; успешный claim выдаёт отдельный random lease
credential. Initial metadata preview ничего не consume: link scanner/unfurl/
prefetch не должен сжигать секрет. Claim/download pinned к canonical API origin,
запрещают redirects/downgrade/alternate ports, передают lease только в
`Authorization`, а cross-origin viewer использует exact CORS allowlist.

### 4G.1 — text и small payload

- Versioned authenticated envelope с hard size bound и encrypted manifest.
- Native create/list/revoke, bounded TTL и claim count, explicit user claim,
  atomic consume и отдельная короткая lease на каждый claim.
- Dedicated cookieless viewer origin (или `credentials: omit` и cookie-ignoring
  API) без third-party resources, analytics, service worker и generic Veil IPC;
  строгий CSP, `no-store` для capability responses, `no-referrer`, `nosniff`,
  `noindex` и generic public errors.
- Browser threat model честно ограничен: malicious Node может подменить viewer
  code во время открытия. Signed native client является более сильным
  code-integrity path.

### 4G.2 — streaming files

- Переиспользуются Phase 3B chunked AEAD и tus только для authenticated creator
  upload с immutable `purpose=secure_share`/`draft_share_id`, one-time binding и
  retention, clamped by share expiry. Dual message/share attachment запрещён.
  Обычный account bearer не расширяется до guest access.
- Отдельная guest download lease ограничена одним share и immutable blob set.
  Filename, MIME, digest, chunk geometry и text находятся в encrypted manifest;
  сервер видит ciphertext size/timing/lifecycle metadata.
- Viewer проверяет полные AEAD chunks с bounded memory. Multi-gigabyte base64
  JSON, Rust `Vec`, JS array или browser `Blob` запрещены. Browser хранит в
  private/OPFS только ciphertext либо plaintext, повторно зашифрованный случайным
  page-lifetime key, и экспортирует лишь проверенный результат; orphan ciphertext
  очищается при startup. Без audited atomic file API используется native fallback. Resume
  совпадает с authenticated chunk boundaries и не публикует partial plaintext
  как завершённый файл.

### Claim, burn и password contract

- Share state: `active -> burned | expired | revoked -> purging`; каждый
  successful claim атомарно увеличивает `consumed_claims` и создаёт собственную
  `issued -> expired | revoked` lease. Abandoned lease остаётся consumed,
  completion ACK является telemetry. Browser resume ограничен жизнью страницы;
  crash/resume разрешён native client только с reviewed OS-protected storage.
- Expiry/revoke commit запрещает новые claim/range/resume requests и помечает
  leases revoked; active responses отменяются best-effort в bounded deadline,
  уже отправленные/буферизованные байты не возвращаются. Burn запрещает новые
  claims, но purge ждёт terminal state ранее выданных leases и затем повторяется
  идемпотентно. Backup retention не реактивирует burned link.
- «Самоуничтожение» означает закрытие последующей серверной авторизации и удаление
  hosted ciphertext после terminal leases. Оно не удаляет уже переданные байты,
  сохранённую копию, screenshot или память получателя — UI не обещает невозможного.
- Legacy downloadable wrapped-key password допускает offline brute force, поэтому
  server rate limit его не защищает. Candidate V1 требует ADR: password как
  server-verified второй gate поверх fragment secret, server-bounded Argon2,
  capability-first checks и единая password+lease transaction. DB theft допускает
  offline guessing verifier; zero-knowledge требует отдельного OPAQUE/PAKE review.

### Abuse boundary и completion gate

Первый релиз разрешает upload только authenticated creator и применяет account/
IP/storage/concurrency quotas, orphan cleanup, emergency disable и operator
revoke. Guest Drop с anonymous upload является отдельным будущим capability и не
входит в 4G. Guest report использует domain-separated report capability, uniform
response и отдельные лимиты, не передаёт root secret и не consume claim. Только
явно выбранный untrusted plaintext раскрывается через consent flow Phase 4F;
официальный builder не читает и не экспортирует protected key stores.

Критерий выхода: secrets отсутствуют в path/query/application log/referrer/
application cache/telemetry, а browser history/sync boundary документирован;
redirect/origin policy fail closed; claim/lease/expiry/revoke races атомарны;
wrong key/password, tamper, truncation,
reorder, cross-share substitution и corrupt resume fail closed; browser CSP/XSS
matrix зелёная; Windows/Linux create и physical text/small/maximum-file/native
crash-resume flows пройдены; browser тестируется только в declared API matrix с
verified temporary publication, а crash/reload/cancel не оставляет readable
plaintext residue; quota, purge retry, backup retention и abuse revoke имеют
integration/operations evidence. До versioned ADR, threat model и security
review функция остаётся `planned/prototype`.

---

## Phase 5 — Android

**Текущее состояние:** Android уже не является изолированным visual prototype.
React Native shell подключён к fail-closed `VeilMobileRuntime` на Rust/UniFFI;
identity хранится через Android Keystore, account/runtime state — в SQLCipher,
а Node Access Pass, authenticated WebSocket, own prekeys, Direct directory,
history-to-live handoff, message projection и idempotent Direct text send/outbox
принадлежат native boundary. Typed ACK deadline и guarded transient reconnect
также готовы. Canonical-origin process-death recovery опубликован и физически
восстановил тот же аккаунт на Samsung S23 без нового Pass или device. Append-only
`PublicFailureCodeV1`, его CI validator, typed Rust/UniFFI/Android mapping и
локальный Android catalog реализованы для identity setup и secure runtime gate;
Direct session/send/delivery и consumer parity для desktop/Go остаются открытыми.
Identity setup теперь использует native durable non-secret v1 journal в
`noBackupFilesDir`: он хранит только random attempt/process UUID, create/restore
mode и ограниченные phase/outcome/revision, без recovery phrase, identity/account
data, origin, Pass или diagnostics. Reconciliation линейризуется с exact
coordinator ownership и strict write-once vault; vault остаётся authority,
terminal receipt сохраняется для at-least-once delivery, а React route остаётся
opaque до проверки текущего foreground epoch. Host-only JVM/Jest gates покрывают
state/fault/replay policy, но не доказывают Android Activity/OS scheduling.
Connected A04/A05 и physical recovery matrix остаются открытыми.
Это всё ещё закрытый Direct Preview: cross-client E2EE text/airplane/background
matrix не готова. Изолированный `internalTester` package/signing contract,
fail-closed APK verifier и ручной protected workflow реализованы, но stable
tester key не предоставлен, подписанный standalone APK не произведён и physical
matrix не выполнялась.

**Beta integration status sync 2026-08-04:** ветка
`ds/beta-all-2026-07-21` включает baseline `f6dbf5a` с отдельным
экспериментальным `/v3/events`, Rust/FFI controller, Android background service
и contacts/create-Direct scaffolding. Это не зелёный integration gate: полный
`cargo test --workspace --all-targets` останавливается на двух ошибках сборки
`veil-ffi`, generated Kotlin bindings не синхронизированы, а mobile route/header/
friend-request contracts расходятся с gateway. Точный состав, результаты
desktop/mobile tests и macOS build evidence записаны в
[`docs/reviews/beta-integration-macos-2026-08-04.md`](docs/reviews/beta-integration-macos-2026-08-04.md).

Следующий порядок: восстановить compile-green `veil-ffi`, регенерировать и
проверить Kotlin bindings, состыковать contact transport с существующими Go/
protobuf contracts и только затем возобновлять physical Android matrix.

**Historical local status sync 2026-07-20:** после UI checkpoint `d65927c`
локальная ветка содержит fail-closed connected-test guard `8e31cc1` и текущий
PublicFailure/setup checkpoint. `origin/codex/mobile-direct-preview` остаётся на
`08a4206`; эти новые локальные checkpoints ещё не являются remote publication.
История на origin уже включает отдельные reviewed security checkpoints:

- `6195c89` — Android WSS использует per-connection `ring`, TLS 1.2/1.3 и
  public WebPKI roots без trust-all/process-global fallback;
- `f13ba4d` — write-once identity vault публикуется атомарно с fsync/readback;
- `91fd2f8` — managed Nginx ingress принимает только две exact legacy REST
  authority-формы и отклоняет остальные 421;
- `88c87bd` — desktop подписывает canonical `host:effective-port`;
- `0bd82d1` — orphaned READY/TERMINAL recovery lease освобождается после
  recreation, тогда как COMMITTING сохраняет ownership;
- `3135297` — debug Ready screen capture ограничен точной foreground generation;
  release, recovery, enrollment, background и Recents остаются защищены;
- `b029a1f` — native recovery/result correlation и strict durable-presence
  verification работают fail closed: `absent` невозможно получить, пока
  coordinator READY/COMMITTING ещё способен опубликовать identity.

Полный pre-split WIP на базе `e751955` сохранён в
`refs/codex/snapshots/mobile-pre-roadmap-sync-20260719-205026` (`73131bb8`) и
`C:\veil-backups\veil-mobile-pre-roadmap-sync-20260719-205026-e751955.bundle`,
SHA-256 `48CA7F65ABD16DFA2F9893E2AB8D0DE2F25A59805D97EF3358DA2E1ED320827F`.
Это восстановительная точка, а не authoritative head. Исходная pause-точка также
сохранена: `f787b83` и
`C:\veil-backups\veil-mobile-pause-2026-07-18-d271140.bundle`, SHA-256
`ADE8C9F2293DEA5E5179417DDAA5BEA3ADFFABA93D16F7F5952A5748206FC7E8`.

Опубликованный recovery checkpoint прошёл TypeScript/ESLint, изолированные
16/16 Jest suites (91/91), Android JVM suite; после coordinator-barrier полный
локальный `:app:testDebugUnitTest` прошёл 227/227. `lintDebug`, debug APK и
androidTest APK также собираются. Connected instrumentation на реальном телефоне
для recovery/vault/capture всё ещё открыта и не подменяется сборкой APK. Generic
Gradle `connected*AndroidTest` теперь fail closed до выполнения task graph и
разрешается только явным одноразовым подтверждением, когда `ANDROID_SERIAL`
точно связывает AGP с единственным свежим single-user emulator без установленного/
retained `io.veil.mobile` или `io.veil.mobile.tester`; проверка повторяется непосредственно перед connected
task action, а task-level `--serial` разрешён только для того же проверенного
emulator. Lifecycle connected tests может удалить target package вместе с
Keystore, SQLCipher и app-private state. Физический телефон запрещён, а work
profile на account-bearing handset не считается disposable boundary. Для явно
разрешённого phone smoke `adb install -r` является лишь non-uninstalling update
path: новый код/миграции всё равно способны изменить state. `firstInstallTime`
и тот же account/vault проверяются после обновления, но не считаются
instrumentation evidence. Все app-project Gradle `install*`/`uninstall*` tasks
теперь безусловно блокируются до execution; guard по-прежнему не распространяется
на manual `adb` и будущие managed-device providers. Для physical instrumentation
нужен отдельный wiped/attested workflow.

**Локальные checkpoints, ещё не на origin:** `d65927c` содержит mobile Island IA/
settings, Circle/Space/Rooms/Voice `DESIGN PREVIEW` и нижний safe-area Direct
composer; `8e31cc1` блокирует generic connected instrumentation на физических
устройствах. Текущий PublicFailure/setup checkpoint не превращает preview-экраны
в runtime-функции и не закрывает app-wide error semantics. Ограниченный Samsung
S23 smoke подтверждает Pass registration, public-WebPKI WSS/signed REST, empty
Direct и same-account force-stop reopen; полная cross-client physical matrix и
signing открыты. Ни snapshot, ни debug/Metro APK не являются tester release.

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

### Transient Direct reconnect checkpoint 2026-07-19

Kotlin-owned transient reconnect зафиксирован отдельным code checkpoint
`62451eb` (`feat(android): add typed Direct reconnect`) в
`codex/mobile-direct-preview`; `master` не изменялся.

**Опубликовано и проверено:**

- production UniFFI adapter переводит в retry permission только generated
  `MobileRetryable(Transport|AckDeadline)` и только на connect, live-buffer,
  live-replay и outbox-replay границах. `Session`, protocol/auth/security и
  storage failures остаются terminal независимо от слов в тексте ошибки;
- одновременно существует не более одного reconnect plan с immutable scope из
  exact session object, lifecycle epoch, canonical origin и expected account ID.
  Повторная аутентификация всегда использует plain bound-account connect: Node
  Access Pass не сохраняется в плане и никогда не replay-ится;
- full-jitter cap растёт `1s → 2s → 4s → 8s → 16s → 32s → 60s` и насыщается на
  60s. Backoff переживает typed connect/bootstrap failure и сбрасывается только
  после нового `Ready` и завершённого durable outbox barrier;
- exact `WAITING → CONNECTING → BOOTSTRAPPING` ownership, connect cancellation и
  transport serialization не позволяют late task, HTTP callback или teardown
  старого поколения отключить новый socket/lease. Background, explicit lock,
  manual disconnect и manual connect отзывают план; другой валидный account и
  `AcceptedSessionInvalid` завершаются fail-closed без retry;
- initial и continuous replay отдельно отвергают противоречивый native DTO
  `ready && outboxReplayRequired`. Scheduler rejection, выполнение task до
  присвоения `ScheduledFuture`, same-account supersession и native success после
  cancellation покрыты детерминированными adversarial tests.

**Completion evidence:**

- `cargo fmt --all -- --check`, workspace clippy с `-D warnings`, полный
  `cargo test --workspace --all-targets` и `git diff --check` зелёные;
- UniFFI и обе Android native ABI дважды воспроизводимо пересобраны. SHA-256:
  generated Kotlin
  `2C18588C73F907E9AB7525BE9ABB8D8C6EFA990AD804DC520D115904B016F995`,
  `arm64-v8a` `.so`
  `691BA9D41E500C46561A1193B30625510371F21AEF12884CC7930860C3B405EC`,
  `x86_64` `.so`
  `86B8368183ED1F494B95633ACF8D646E797C01A9E1CA35BAC47710B97547940E`;
- `verifyVeilRustLibraries`, полный JVM suite 172/172, focused runtime 87/87,
  `lintDebug` и `assembleDebug` прошли для `arm64-v8a,x86_64`; debug APK содержит
  обе ABI;
- frozen pnpm install, ESLint, TypeScript и Jest 80/80 зелёные. Независимые
  security/race и test-matrix exact-diff аудиты после всех исправлений не нашли
  P0/P1/P2.

Локальный APK этого checkpoint остаётся build evidence с debug key. Он не
является tester release и не заменяет clean-install/physical-device evidence.

**Следующий порядок:**

1. Сохранить выбранный canonical origin native-side для безопасного
   process-death recovery без хранения или повторного использования Node Access
   Pass; восстановление обязано повторно подтвердить тот же account ID.
2. Пройти clean process restart, airplane-mode/reconnect и физическую
   Desktop ↔ Android Direct matrix, включая late callback и lock/background.
3. Только после этой матрицы собрать и проверить подписанный standalone tester
   APK; затем переходить к push publication, Circle, Space/Rooms, attachments и
   корректному multi-device.

Ранее обязательные исправления проекта — текущий статус:

- Закрыто: TypeScript использует совместимые `module: esnext` и
  `moduleResolution: bundler`.
- Закрыто: ESLint/Jest dependencies и unit/component/runtime suites подключены.
- Закрыто для production boundary: raw JS crypto mock/sign/AEAD surface удалён;
  отсутствие native module приводит к fail-closed ошибке.
- Решение сохранено: React Navigation + StyleSheet остаются оболочкой; миграция
  на NativeWind/Expo Router без измеримой пользы не планируется.

### Phase 5A — Android foundation

**Foundation checkpoint 2026-07-19: в работе.** Android project теперь
versioned; Rust/UniFFI воспроизводимо собирается для `arm64-v8a` и `x86_64`.
Удалён runtime crypto mock и raw sign/AEAD JS surface, release больше не может
подписываться debug key. Recovery phrase хранится через Android Keystore-wrapped
AES-GCM vault, backup отключён, secret screens используют `FLAG_SECURE`, copy в
clipboard удалён и добавлено подтверждение слов. Состояния local identity и
native failure разделены. Это закрывает первый пункт и часть пунктов 3–5 ниже,
а SQLCipher, lifecycle lock policy и authenticated mobile runtime теперь
подключены. Fail-closed canonical-origin process-death recovery реализован,
прошёл automated gate и физически восстановил тот же аккаунт без повторного
Pass/нового device после принудительной остановки процесса. Standalone signing и
оставшаяся airplane/background/biometric matrix открыты и не позволяют считать
5A завершённой.

**Physical Android TLS P1 2026-07-19 — исправлено и физически подтверждено:**
stock Android подтвердил первый pre-network blocker: Rust path через
`rustls-native-certs` не находит Android PEM CA bundle. После перевода Android на
`webpki-roots` изолированный точный probe обнаружил второй blocker: feature graph
содержал `rustls` только со `std`, без `ring` или `aws-lc-rs`, поэтому
`ClientConfig::builder()` паниковал до TLS ClientHello. Это точно объясняет DNS без
запроса в Nginx и generic secure-action error. Исправленный `arm64-v8a` runtime
прошёл реальную WSS-аутентификацию, signed REST prekey count/upload и directory
bootstrap через `veil.erez.pro` на Samsung S23; insecure fallback не вводился.

Опубликованный checkpoint `6195c89` задаёт явный режим `PublicWebPKI`: per-connection
`Connector::Rustls`, `ClientConfig::builder_with_provider(ring)`, непустые Android
`webpki-roots`, target-specific native roots для desktop и один проверяемый набор
TLS 1.2/1.3. Process-global `install_default`, trust-all, hostname/SNI bypass,
HTTP fallback и принятие неизвестного CA запрещены. Certificate/provider/store
failure остаётся terminal epoch failure и не может ослабляться reconnect-ом.

Это ещё не общая поддержка произвольной self-hosted private CA. До такого claim
нужен versioned `NodeTrustPolicyV1`, origin- и Node-identity-bound, хранимый в
SQLCipher/Rust и одинаково применяемый к WSS, REST, uploads и push bootstrap.
Минимальные режимы: `PublicWebPki`, явно enrolled `PrivateCa` и отдельно reviewed
enterprise `AndroidManagedTrust`; Node Access Pass не является TLS trust proof.
Сейчас Rust WSS и Android OkHttp REST имеют разные trust providers, что допустимо
для Preview с одной валидной public chain только под cross-transport tests, но не
для общего private-CA режима.

**Atomic identity vault P1 — опубликовано в `f13ba4d`:** staged record проходит
file fsync и readback, staging/parent directory fsync, затем атомарно публикуется
rename-ом непустого каталога и повторно читается. Existing legacy file и уже
непустой published directory никогда не перезаписываются. Unit gate и сборка
instrumentation APK зелёные; connected concurrent-writer/power-loss/device
instrumentation остаётся обязательной evidence.

**Legacy REST-v1 authority compatibility P1 2026-07-19 — mitigated и
опубликовано; protocol scope открыт:** Android подписывал
canonical `veil.erez.pro:443`, а опубликованный desktop после WHATWG URL
normalization подписывает `veil.erez.pro`; текущий Nginx `$host` передаёт upstream
форму без порта. Жёсткий rewrite к `:443` исправил бы Android, но немедленно сломал
бы текущий desktop 401. Поэтому managed transitional ingress обязан принимать
ровно две legacy authority-формы через exact allowlist, передавать выбранный
литеральный результат byte-for-byte и отвечать 421 на любое другое имя/порт.
Checkpoint `91fd2f8` публикует exact-allowlist Nginx bridge, а `88c87bd` переводит
desktop на единый effective-port authority. Bridge развёрнут на VPS и проверен
HTTP/1.1/HTTP/2/WS harness-ом; Android physical signed REST probe прошёл.
Остаются physical desktop ↔ Node compatibility probe и удаление transitional
bridge после перехода на REST v2.

Bridge не закрывает фундаментальный REST v1 scope. Дополнительно подтверждено,
что gateway за HTTP reverse proxy выводит Veil Link URL из `r.TLS`/`r.Host` и
может породить `http://veil.erez.pro:443/...`. До Space/Veil Link claim Node обязан
получить fail-closed configured `VEIL_PUBLIC_ORIGIN`; REST v2 и WS v3 должны
подписывать/проверять тот же origin независимо от входного Host.

**Empty-account Direct Ready P1 2026-07-19 — исправлено и физически
подтверждено:** первая закрытая регистрация полностью коммитила account, device и
21 prekey, но после успешного пустого directory Android возвращался на экран
Node. Причина была локальной: exact outbox replay ошибочно требовал presentation
self-row из `identity_directory_v1`, которого у аккаунта без разговоров законно
нет, и повышал отсутствие кэша до `StorageUncertain`. Authoritative immutable
`authenticated_self_bindings_v1`, exact user, active device/installation markers,
account keys и alias/conflict checks при этом были целы.

Fix оставляет presentation self-row опциональным corroborating cache, но не
ослабляет ни одну authoritative self/device/peer/ratchet проверку и не создаёт
синтетический directory snapshot. Store regressions доказывают zero-row success и
conflict fail-closed; полный UniFFI regression проходит
`empty directory → terminal history → live quiescence → empty outbox → Ready`.
На физическом Samsung S23 тот же сохранённый аккаунт открыл пустой Direct, затем
пережил `am force-stop` и снова аутентифицировался без нового Pass/account/device;
Node наблюдал полный bootstrap и одно активное соединение без auth failure.
Исправление опубликовано отдельным checkpoint `7cae239`; чистая кандидатная
worktree прошла `cargo fmt --check`, scoped `clippy -D warnings`, 82/82 теста
`veil-ffi` и 90/90 тестов `veil-store`.

### Whole-app lifecycle / Node Access Pass authority P1 2026-07-19

**Исправлено, независимо проверено и опубликовано в `7a7802b`.** Старый
`MainActivity.onStop` считал запуск внутренней `RecoveryActivity` уходом всего
приложения в фон и мог стереть process-local Pass во время Pass-first identity
ceremony. Дополнительный запоздалый React Native AppState callback мог выбрать
background lock, а затем после медленного transport teardown стереть уже новый
Pass, staged вернувшимся foreground Intent.

Foreground/background authority теперь принадлежит process-wide Activity gate,
который считает только exact `MainActivity` и `RecoveryActivity`; dependency,
UnifiedPush и debug Activity не могут открыть или удержать native runtime.
Внутренний handoff и configuration recreation не создают ложный background.
Нулевое число доверенных Activity проверяется на следующем main-loop turn;
foreground enrollment Intent пересекает native barrier **до** разбора/staging
секретного fragment и получает fail-closed watchdog, если Activity так и не
стартовала.

Pass revocation, lifecycle epoch и выбор закрываемой session capability теперь
линеаризуются под одним `stateLock`; поздний disconnect/close не может удалить
Pass более нового foreground epoch. Explicit lock остаётся безусловным, а
AppState bridge использует только conditional background companion.
Независимый re-review завершён с `P0=0, P1=0`; exact шестефайловый кандидат в
отдельной detached worktree прошёл `verifyVeilRustLibraries` и полный
`:app:testDebugUnitTest` (`BUILD SUCCESSFUL`, 229 actionable tasks). Реальные
`singleTask onNewIntent`, `Main → Recovery`, rotation и Home/background остаются
обязательной instrumentation/physical матрицей до подписанного tester APK.

### Native recovery, orphan lease и Ready capture 2026-07-19

`0bd82d1` освобождает orphaned recovery lease в READY/TERMINAL после process
recreation, но никогда не отбирает COMMITTING у worker. `3135297` разрешает
capture только debug Ready shell с точной foreground generation; stale queued
clear после pause/new Intent не может снять `FLAG_SECURE`, а release compile-time
запрещает downgrade. `b029a1f` закрепляет native-only recovery UI, correlated
terminal outcomes и строгую durable-presence проверку. Coordinator держит barrier
на всём vault-read: READY/COMMITTING всегда дают unknown, поэтому UI не может
посоветовать уничтожить единственную фразу до окончательного terminal результата.
Физическая API ≤32/API 33+ OEM-матрица для screenshot/recording/Recents,
process-death, autofill/accessibility и concurrent recovery остаётся открытой.

### Public failure codes v1 — обязательный gate 5A/5B

**Статус 2026-07-20: Android setup/runtime-gate и Direct send/delivery action
slice реализованы host-only; app-wide consumer и общий rollout ещё не закрыты.**
Machine-readable registry, immutable history, schema/append-only validator и CI
синхронизируют точные Kotlin/TypeScript allowlist. Rust/UniFFI передаёт typed
`Transport`, `AuthRejected`, `RegistrationClosed`, `InviteInvalid`, `EpochInvalid`
и `StorageUncertain`; Android не анализирует exception/server text, разделяет
локальные Pass/binding failures и публикует только sanitised internal code плюс
`userInfo.publicFailureCodeV1` для secure runtime gate. React Native имеет reviewed
catalog всех 18 кодов и в setup/runtime gate закрывает unknown/malformed/conflicting
outcomes через `VEIL-RUNTIME-999`. Direct definite non-send и durable delivery
unknown теперь разделены как `VEIL-DIRECT-001/002`; malformed/conflicting metadata,
session и mixed unavailable outcomes остаются честным `VEIL-RUNTIME-999`.
Desktop и Go consumers, локали кроме текущего Android catalog, более узкий Direct
session outcome и общий cross-client conformance gate остаются открытыми.
Exact routing, UI actions, host evidence и non-claims записаны в
[`docs/reviews/android-direct-public-failure-action-contract.md`](docs/reviews/android-direct-public-failure-action-contract.md).

До подписанного tester APK используется append-only `PublicFailureCodeV1` с единым
machine-readable registry под `veil-proto`, одинаковым для Rust, Go, desktop,
Android и будущих клиентов. Публичная карточка ошибки состоит из независимых
`title + description + next action + code`; код ASCII, доступен для копирования,
не переводится и не содержит идентификатор события. Текст и действие выбираются
только из локального reviewed catalog по коду: native/server message, URL, HTTP
body или `String(error)` никогда не рендерятся.

Минимальный каталог для закрытия текущего Android Direct Preview:

| Публичный код | Стабильная семантика и безопасное действие |
|---|---|
| `VEIL-SETUP-001` | protected ceremony UI не был показан; provisional native lease освобождён и durable identity change не подтверждён, закрыть Veil и повторить |
| `VEIL-SETUP-002` | ceremony/lease/result либо публикация identity не подтверждены: сохранить phrase и блокировать новый setup; для BUSY/unknown start даже authoritative vault `absent` недостаточно, пока native не подтвердил settled ceremony/lease. Уничтожать новую create-фразу и начинать заново можно только после native-settled + authoritative `absent`, любая ошибка остаётся `unknown` |
| `VEIL-LOCAL-001` | локальный аккаунт locked/not ready; открыть тот же аккаунт и повторить |
| `VEIL-LOCAL-002` | encrypted vault/SQLCipher не открылся; перезапустить Veil, не создавать новую recovery phrase |
| `VEIL-LOCAL-003` | локальное secure state нельзя подтвердить; lock/reopen, сеть и chat остаются закрытыми |
| `VEIL-NODE-001` | Node origin не является точным canonical HTTPS origin; исправить адрес |
| `VEIL-NODE-002` | только typed retryable transport; проверить сеть, безопасный reconnect использует тот же аккаунт |
| `VEIL-NODE-003` | generic authentication rejection либо pre-proof failure; повторить с тем же local account без раскрытия account/Pass oracle |
| `VEIL-NODE-004` | TLS/protocol/authenticated binding/epoch response не прошёл проверку; соединение отвергнуто |
| `VEIL-PASS-001` | Node требует Access Pass; показывается только по typed `REGISTRATION_CLOSED` после account-key proof |
| `VEIL-PASS-002` | Pass invalid/expired/already used; показывается только по typed `INVITE_INVALID` после account-key proof |
| `VEIL-PASS-003` | pending Pass локально отсутствует, истёк или изменился; сохранить аккаунт и открыть свежий Pass |
| `VEIL-RUNTIME-001` | предыдущая secure operation ещё завершается; подождать и повторить |
| `VEIL-RUNTIME-002` | operation отменена lifecycle/lock; вернуться в Veil и повторить с тем же аккаунтом |
| `VEIL-SYNC-001` | аккаунт аутентифицирован и сохранён, но Direct bootstrap не завершён; reconnect без нового Pass |
| `VEIL-RUNTIME-999` | неизвестный, malformed или ещё не рассмотренный outcome; generic fail-closed fallback |
| `VEIL-DIRECT-001` | typed definite non-send либо durable failed; сохранить/исправить текст, новый send только как новый explicit intent при отдельно подтверждённом текущем Ready generation |
| `VEIL-DIRECT-002` | durable delivery unknown; исходное сообщение могло дойти, сохранить и ждать authenticated reconciliation без blind resend |

Коды описывают только безопасную presentation/recovery семантику. **Публичный
код никогда не разрешает retry, reconnect, Pass replay или ослабление trust.**
Единственный источник такого разрешения — положительная типизированная native
allowlist (`MobileRetryable(Transport|AckDeadline)` и её будущие reviewed
версии); неизвестный enum/value всегда terminal. Безопасные enrollment-различия
берутся из `AuthFailureReason`, проходят Rust/UniFFI как enum и никогда не
восстанавливаются сравнением либо поиском подстроки.

Registry хранит immutable code, semantic key, exposure gate, recovery-action key
и retired/reserved state. Удалённый код и его numeric/string identity навсегда
резервируются. Внутренние `E_VEIL_*`, HTTP status, серверные `publicerr` snake-case
codes и tus `ERR_*` остаются отдельными слоями и сопоставляются явно; они не
переименовываются автоматически в публичный код. Поле `Error.reason = 5` уже
принадлежит correlated Direct send contract и не может быть перегружено общим
public failure code; если WS v2/v3 понадобится новый wire field, он добавляется
под новым protobuf number.

Support diagnostics могут содержать public code, build/OS, bounded stage enum,
typed private error class, reconnect ordinal, краткоживущий случайный
`support_ref` и HMAC reference для origin. Recovery phrase, Pass/token/digest,
ключи, ciphertext/plaintext, raw URL/path, account/device/message IDs и native
exception text запрещены. `support_ref` показывается только если соответствующая
санитизированная локальная запись действительно создана; публичный код сам по
себе остаётся общей причиной, а не occurrence identifier.

Обязательный CI/gate:

- schema проверяет формат, уникальность, append-only history, reserved codes и
  parity semantic/action keys; unknown всегда отображается как
  `VEIL-RUNTIME-999` и остаётся terminal;
- fixture каждого typed Rust/server outcome даёт один и тот же public code в
  Android и desktop; mappings исчерпывающие, а Go/Rust/Kotlin/TypeScript не
  распознают security outcome по тексту;
- anti-oracle tests сводят все pre-proof/unknown auth failures к
  `VEIL-NODE-003`; `VEIL-PASS-001/002` допустимы только после подтверждённого
  account-key proof;
- secret-canary tests запрещают перенос native/server cause, Pass, identity,
  origin/path и SQL/crypto details в UI, logs, crash report и accessibility tree;
- retry tests доказывают, что подмена public code, message, locale или server
  payload не может создать reconnect capability; решение принимает только
  typed native allowlist;
- component/a11y tests проверяют title, понятное description, конкретный next
  action, читаемый/копируемый code, long-text и deterministic English fallback.

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
   transient reconnect и automated process-death recovery подключены. Реальная
   airplane/process-kill matrix остаётся release evidence.
7. Enrollment второго устройства и revoke flow проходят отдельный secure QR
   gate 5C как prerequisite для групп, server channels и MLS.
8. Android Back закрывает dialog/sheet, затем возвращает к Rooms/Spaces либо
   предыдущему native route, и только потом покидает экран.
9. Профилировать blur, HebrewRain и текущие четыре одновременно смонтированные
   pager page на слабых устройствах; целевой route не держит невидимые тяжёлые
   экраны без необходимости и respect reduced motion/battery saver.
10. Перевести prototype на общий 4E navigation contract: корневые Home и единый
    список Circles/Spaces, Direct внутри Home, Circle сразу в chat, Space →
    Rooms → Room, Members и Identity как bottom sheets. Это меняет presentation/
    navigation, но не даёт JS доступ к crypto state.
11. Разделить screen-capture boundaries: recovery phrase, Access Pass, device-link
    secret/SAS, bootstrap/lock/reconnect и background всегда native-secure;
    Recents snapshot всегда скрыт независимо. Полностью Ready content может
    разрешать screenshot/recording только через отдельную явную privacy-настройку
    (release default — запрещено), причём JS не может снять обязательную native
    reason. Debug Preview может иметь отдельный compile-time opt-in для визуальной
    обратной связи, не меняющий release policy. Android ≤12 и MediaProjection/
    pause race требуют отдельной physical matrix до общего opt-in.
12. До подписанного/public tester APK генерировать Android third-party notices,
    включать полные upstream licenses (включая ISC/MIT Lucide/Feather) в APK и
    `About → Open-source licenses`, а CI обязан сверять inventory с lockfile.

Результат 5A: подписанный internal APK запускается на чистом устройстве,
создаёт/восстанавливает identity, переживает restart, безопасно lock/unlock и
соединяется с тестовым gateway без доступа JS к секретному состоянию. Все
setup/local/Node/Pass/runtime outcomes из каталога v1 имеют одинаковые code,
description и next action на Android и desktop fixtures; неизвестный outcome
остаётся `VEIL-RUNTIME-999`, а ни один публичный код не даёт retry authority.

### Phase 5B — Android messaging

**Direct text checkpoint 2026-07-19: частично готов.** Настоящие Direct list,
authenticated history, bounded live receive, native projection, X3DH one-shot
peer-prekey и idempotent SQLCipher-owned send/outbox опубликованы в цепочке
`029d1e3`…`aaaf1df`; `7cae239` отдельно закрывает automated true-empty Ready.
Typed ACK deadline, transient reconnect и automated process-death recovery
реализованы. Ограниченный S23 same-account force-stop smoke зелёный, но полная
Desktop ↔ Android send/delivery/outbox/reconnect/airplane/background/process-death
physical matrix, private groups и остальные пункты 5B не готовы.

Process-death contract хранит в SQLCipher только singleton
`canonical_server_origin + expected_user_id`, выбранный атомарно вместе с
immutable authenticated-self binding после успешной mobile-аутентификации.
Node Access Pass, WebSocket URL и ключи не персистятся. При новом процессе Rust
повторно проверяет canonical origin, exact user, self binding и текущие
mnemonic-derived identity/signing keys; legacy БД без явного singleton не
угадывает target. Android создаёт один zero-delay plain reconnect, сохраняет
typed backoff с ordinal 0 после первой разрешённой ошибки и линейно уступает
новому staged Pass. Manual disconnect остаётся non-destructive и сохраняет
target; отдельного `Forget Node / remain offline` API пока нет.

Host-only precursor D03 от 2026-07-20 закрывает именно native persistence и
ACK reconciliation для неоднозначной доставки: после первого accept в
детерминированном server ledger полная `VeilMobileSession` уничтожается до
локального ACK, затем тот же file-backed SQLCipher store открывается заново.
Replay сохраняет exact client ID/header/ciphertext/encoded payload, ratchet
остаётся продвинут ровно один раз, повторный accept возвращает прежний receipt,
а production protobuf decoder и deferred FIFO сводят outbox и projection к
одной `Sent` строке. Конфликт того же client ID с другими ciphertext bytes
отклоняется без мутации ledger. Это automated test oracle, а не реальный Veil
Node, Android OS process-death или physical-device evidence; строка D03
физической матрицы и полный exit gate 5B остаются открыты.

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
8. Direct session/send/delivery, push, Circle, Space/Rooms, attachment и
   multi-device failures расширяют тот же append-only registry до появления
   соответствующего UI; новый transport не вводит параллельные коды или raw
   server/native text.

Exit gate 5B для честного Direct Preview дополнительно требует одинаковую
Desktop ↔ Android failure matrix для prekey, directory, history, live replay,
outbox/ACK и process-death reconnect. Post-auth failure показывает
`VEIL-SYNC-001` и сохраняет точное указание «аккаунт сохранён; reconnect без
нового Pass»; pre-auth, storage-uncertain и delivery-unknown outcomes не
смешиваются с ним. Physical tests подтверждают, что code/description/action
переживают locale и process restart, а retry по-прежнему определяется только
typed native allowlist.

### Phase 5C — Secure QR device linking / multi-device gate

**Статус: не начато; blocking для корректного multi-device.** Сканирование QR
само по себе не авторизует устройство. Уже активное доверенное устройство и новое
устройство устанавливают отдельный versioned pairing-сеанс, сравнивают одинаковый
SAS и только после явного подтверждения переводят новый device binding в active.
Если активного устройства нет, используется отдельный reviewed recovery flow, а
не ослабленная разновидность QR enrollment. Этот QR не является Veil Link, Node
Access Pass или QR-проверкой чужого fingerprint и не переиспользует их parser/
authority semantics.

Обязательный контракт:

- UI использует стандартный совместимый QR Code с сохранёнными quiet zone,
  контрастом и error correction. Veil branding, правильный логотип, островная
  рамка и countdown находятся вне машинно-читаемой области; custom QR alphabet
  и декоративная подмена модулей запрещены;
- QR содержит только versioned одноразовый pairing offer: exact canonical Node
  origin, случайный challenge/offer ID, ephemeral public key, protocol version и
  короткий expiry. Recovery phrase, mnemonic/root/account private key, SQLCipher
  key, bearer/session token и постоянный секрет через QR, relay или clipboard не
  передаются;
- обе стороны создают независимые ephemeral keys. Canonical transcript включает
  exact Node `(scheme, host, effective port)` и TLS identity, account binding,
  offer/challenge, оба ephemeral keys, оба device IDs и device public keys,
  запрошенные/разрешённые capabilities, protocol version и expiry. Любая смена
  origin, relay, ключа, device или capability меняет transcript и SAS;
- SAS выводится из подтверждённого transcript и показывается одинаковым коротким
  кодом на обоих экранах. Пользователь сравнивает его и явно нажимает Approve на
  обоих устройствах; scan, совпадение account name или ответ Node не являются
  согласием. Mismatch/Cancel немедленно отзывает pairing-сеанс;
- offer имеет короткий TTL, single-use compare-and-consume и bounded attempts.
  Повтор, delayed relay, concurrent redemption, replay после Cancel/expiry и
  второй transcript для того же offer отклоняются без создания активного device;
- Node хранит state machine `pending → active | expired | cancelled`. Переход в
  `active` атомарно проверяет обе approval proofs, неизменный transcript,
  capability policy и ещё активное авторизующее устройство; crash/retry
  идемпотентен и не оставляет частично активный roster/prekey/push state;
- новый device получает только собственные device secrets и подписанное
  разрешение аккаунта. Авторизующее устройство не экспортирует recovery/root
  secret. После activation публикуются exact-device prekeys/capabilities; до
  завершения roster reconciliation отправка, требующая нового roster, остаётся
  fail closed;
- Settings показывают device fingerprint, capabilities, время/способ enrollment
  и last seen. Revoke требует явного подтверждения, немедленно блокирует новые
  session/prekey/push операции устройства и запускает нужную key/roster rotation.
  Pending/approve/activate/cancel/expire/revoke фиксируются в bounded audit без
  секретов; Node audit не является единственным источником истины для клиентов.

Security/physical exit matrix включает hostile Node и hostile relay: QR/origin/
TLS substitution, MITM ephemeral-key swap, device/key/capability escalation или
downgrade, SAS mismatch, malformed/oversized QR, expired/replayed/concurrently
redeemed offer, authorizer revoke во время approval и reordered/duplicated
responses. Process death, background/lock и network loss проверяются на каждом
переходе: после восстановления получается либо тот же exact active binding, либо
безопасно cancelled/expired pending, но никогда новый binding или activation с
изменённым transcript.

Accessibility fallback обязателен: camera permission можно отклонить, после чего
доступен ручной ввод versioned pairing code с теми же TTL/transcript/SAS
проверками; SAS читается screen reader, разбит на однозначные группы и не зависит
от цвета/анимации. Large text, high contrast, reduced motion, TalkBack/VoiceOver
и keyboard navigation входят в physical matrix. Gate закрывается только после
Desktop ↔ Android и Android ↔ Android тестов, независимого security review и
доказательства, что hostile Node/relay не может активировать, подменить или
расширить capabilities нового устройства без совпавшего SAS и двух approvals.

Оценка: закрытый Android DM-MVP — примерно 8–12 недель одного опытного
разработчика. Groups/servers, push previews и attachments добавят ещё 4–8
недель; полная desktop parity потребует отдельного многомесячного этапа и
независимого security review.

---

## Phase 5S — Direct protocol assurance, `libsignal` decision и hostile Node

**Статус 2026-07-20: открыт; блокирует stable и финальный multi-device design,
но не требует аварийной замены работающего Preview-протокола.** X3DH, Double
Ratchet и Sender Keys в Veil —
собственные protocol implementations поверх стандартных примитивов. Текущие
инварианты, тесты и fail-closed поведение снижают риск, но не заменяют независимый
криптографический аудит и сами по себе не доказывают отсутствие protocol bug.
На сегодня конкретный exploit в Direct cryptography не установлен. Отдельный
подтверждённый cross-Node credential-scope P1 в WebSocket authentication и
связанной REST authority-модели записан в 5S.3 и должен быть закрыт до
production/multi-Node claims.

**Checkpoint 5S.1A 2026-07-20:** добавлен immutable синтетический Direct-v1
transcript с SHA-256, executable primitive oracle, production `veil-client`
hydrate/encrypt/decrypt negative matrix и file-backed SQLCipher CAS `0 → 1`.
Инъекция фиксированных X3DH/ratchet secrets в общие transitions доступна только
crate-private `cfg(test)` коду, а fixed nonce используется отдельным test oracle;
production randomness не ослаблена. Это покрывает shared Rust boundary, но ещё
не Android FFI/UI или отдельный desktop runtime consumer. Точный scope, findings
и non-claims записаны в
[`docs/reviews/phase-5s-direct-v1-transcript-checkpoint.md`](docs/reviews/phase-5s-direct-v1-transcript-checkpoint.md).

**Local checkpoint 5S.1B 2026-07-20:** findings 1–2 получили host-only
hardening: public `VeilClient::establish_session` требует exact совпадение
peer/bundle identity до mutation, а received ratchet DH проверяет фактический
X25519 contributory result до публикации state. Frozen Direct-v1 SHA
`DAD0A84E5D7366E5189B24C9FB230C4BDD4CC67245607C148B3E3003D9915C2E`, wire и
stored-state format не изменились. Scope, host evidence и non-claims
зафиксированы в
[`docs/reviews/phase-5s-direct-v1-key-validation-checkpoint.md`](docs/reviews/phase-5s-direct-v1-key-validation-checkpoint.md).

**Local checkpoint 5S.1C 2026-07-20:** finding 5 получил host-only hardening:
persisted skipped keys имеют canonical bounded decoder/writer и deterministic
capacity failure без eviction; все live transitions используют exact
revision-and-bytes SQLCipher CAS, initial publication остаётся insert-only, а
legacy rowid-backed `ratchet_sessions` losslessly мигрируется в `WITHOUT ROWID`
в одной `BEGIN IMMEDIATE` transaction с capacity guards. Exact allowlist трёх
исторических DDL-вариантов, PK topology и main/TEMP dependencies отклоняет
future constraints, autoindexes и reserved-name collisions до любой mutation;
для самой старой схемы `revision = 0` синтезируется только внутри rebuild.
Stale history/general receivers, process reopen, malformed state, FFI
recanonicalization и rollback покрыты executable tests. Frozen Direct-v1 SHA не
изменился. Scope, физическая schema migration, residual risks и non-claims
зафиксированы в
[`docs/reviews/phase-5s-direct-v1-skipped-key-state-checkpoint.md`](docs/reviews/phase-5s-direct-v1-skipped-key-state-checkpoint.md).

Findings 3–4, deterministic skipped-key expiry, whole-file rollback, hostile
Node, key transparency, session lifecycle, cross-client consumption,
full `libsignal` adapter/ABI/state spike и независимый внешний аудит остаются
открытыми. Pinned upstream source/build checkpoint 5S.2A is recorded in
[`docs/reviews/phase-5s-libsignal-isolated-spike.md`](docs/reviews/phase-5s-libsignal-isolated-spike.md);
it did not integrate or activate the library.

### 5S.1 — Зафиксировать и атаковать текущий Direct v1

1. Опубликовать exact executable contract для identity/prekey bundle, X3DH
   transcript, Double Ratchet header/AAD, state serialization, skipped-key bounds,
   replay rules, atomic SQLCipher transitions и domain separation. Формулировки
   «похоже на Signal» недостаточно: каждый byte и state transition должен быть
   versioned и воспроизводим desktop/mobile fixtures.
2. Сопоставить контракт с актуальными официальными спецификациями
   [X3DH](https://signal.org/docs/specifications/x3dh/),
   [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) и
   [Sesame](https://signal.org/docs/specifications/sesame/). PQXDH и новые ratchet
   variants исследуются отдельно и не выдаются за уже реализованные свойства.
3. Добавить adversarial/property/fuzz corpus: forged/tampered header, invalid и
   low-order keys, replay/stale one-time prekey, simultaneous initiation,
   out-of-order/duplicate messages, skipped-key exhaustion, rollback/process death,
   session replacement и downgrade. Ошибка никогда не переключает Direct на
   plaintext и не коммитит candidate state до успешной authentication.
4. Перед stable заказать независимый аудит как минимум `veil-crypto` Direct,
   `veil-client` orchestration, SQLCipher transaction boundary, FFI serialization
   и server prekey/envelope handling. Findings должны быть исправлены либо явно
   приняты с owner, scope и сроком; внутренний review не закрывает этот пункт.
5. Отдельно закрыть известный session-lifecycle availability gap: текущая модель
   хранит одну ratchet-session на peer identity и не реализует Sesame-подобный
   current/previous per-device session set. Simultaneous initiation, восстановление
   и новый device не должны приводить к silent reset, undecryptable loop или
   повторному использованию prekey; это требуется решить до proper multi-device.

### 5S.2 — Изолированный официальный `libsignal` spike, не blind rewrite

1. В отдельном crate/ветке проверить официальный
   [`signalapp/libsignal`](https://github.com/signalapp/libsignal) на Android,
   Windows и Linux: reproducible/pinned build, размер, latency, crash recovery,
   SQLCipher-backed stores и совместимость с текущей Rust/UniFFI границей.
2. Учесть, что upstream прямо считает external use unsupported, а API и bridge
   могут меняться без предупреждения. Совместимая AGPL-лицензия и Rust core не
   делают библиотеку drop-in или автоматически аудированной интеграцией Veil.
   Актуальный upstream ориентирован на PQXDH/современный ratchet lifecycle, поэтому
   он не является бинарно совместимой реализацией текущего Veil X3DH profile.
3. Зафиксировать полный migration impact: server prekey API, protobuf/envelopes,
   identity/device addressing, session serialization, local DB, desktop/mobile
   bridges, Sender Keys и multi-device orchestration. Нельзя молча сбросить
   существующие sessions или объявить старый ciphertext новым форматом.
4. ADR выбирает один из двух честных результатов:
   - audited/hardened Veil Direct v1 остаётся основным; либо
   - появляется capability-negotiated `direct_v2_libsignal` с отдельным wire/state
     version, no-downgrade правилом и проверяемой миграцией.
   Production switch разрешён только после cross-client fixtures, rollback plan и
   отдельного review самой интеграции.
5. `libsignal` не решает Node credential scoping, canonical-origin enforcement,
   REST request authentication, first-contact key transparency или авторизацию
   membership epoch в Circle/Space. Эти независимые границы остаются blocking
   gates при любом результате spike.

### 5S.3 — Злонамеренный или скомпрометированный Veil Node

Node не получает автоматического права расшифровать корректно установленную E2EE
session, но остаётся активным противником, а не только relay. До закрытия gate
нужно доказать безопасное поведение при следующих атаках:

**Known cross-Node credential-scope P1 2026-07-19:** это одна граница доверия,
проявляющаяся в обоих текущих transport authentication paths:

- `veil-ws-auth-v2` подписывает server challenge, DH result и account/device proof,
  но не включает exact canonical Node origin или TLS channel binding.
  Злонамеренный Node A может в пределах challenge TTL переслать challenge Node B
  подключившемуся к A клиенту и вернуть подписи в B. Relay применим не только когда
  та же account identity уже существует на B: альтернативные prerequisites —
  открытая регистрация B либо действующий B Node Access Pass, полученный A вне
  proof. Registration intent и сам Pass/его commitment сейчас не входят в
  подписанный transcript, поэтому Pass можно подставить на стороне B;
- REST v1 server выводит security origin из request `Host` и принимает identity из
  `X-Veil-User`, не подписанного как часть полного origin/user request context.
  Безопасность такого forwarding зависит от ingress/gateway, а не от
  самодостаточного end-to-end proof; доверять произвольному `Host` как собственному
  public origin нельзя.

Interim checkpoints `91fd2f8` и `88c87bd` закрывают конкретное legacy authority
расхождение на управляемом ingress: allowlist принимает только bare host и
canonical `:443`, передаёт literal Host/XFH и отклоняет остальное 421, а desktop
подписывает effective port. Это не добавляет cryptographic canonical-origin/user
binding и не закрывает WS v3/REST v2/two-Node hostile-relay exit gate.

**Local checkpoint 5S.3A 2026-07-20:** без активации transport добавлен один
binary exact-origin authentication contract для Rust и Go. Domain-separated
Node Access Pass commitment связывает bearer с canonical origin; WS v3
аутентифицирует origin, challenge, account keys, device id, предварительно
проверенный binding commitment и явный existing/open/Pass intent двумя
связанными account/device proofs; REST v2 подписывает origin, UUID пользователя,
method, exact bounded request target, timestamp, fresh nonce и digest exact body.
Immutable synthetic fixture
`test-vectors/transport-auth/v1.json` с SHA-256
`c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc`
исполняется обоими runtime languages. Точный контракт и non-claims записаны в
[`docs/adr/0003-origin-bound-transport-authentication.md`](docs/adr/0003-origin-bound-transport-authentication.md)
и
[`docs/reviews/phase-5s-hostile-node-auth-contract-checkpoint.md`](docs/reviews/phase-5s-hostile-node-auth-contract-checkpoint.md).
Ни gateway/protobuf/middleware, ни Node config/deploy/compatibility policy этим
checkpoint не меняются: P1 остаётся открытым до mandatory configured origin,
live fail-closed cutover и реальной two-Node relay matrix.

**Local checkpoint 5S.3B-1 2026-07-20:** добавлен обязательный
`VEIL_PUBLIC_ORIGIN` с exact canonical explicit-port значениями для local
Compose и managed deployment; оба gateway Compose path используют required
substitution без production fallback, а документация фиксирует fail-closed
startup boundary. Это только non-deployed configured-origin foundation:
текущие `/ws` и signed REST остаются legacy Preview WS auth v2/REST auth v1,
никакой live Node/config activation не выполнено, P1 и Phase 5S остаются
открытыми. Phone/ADB/APK/Pass/recovery testing по-прежнему отложен до явного
возобновления и подтверждённо записанной recovery phrase.

**Local checkpoint 5S.3B-2 2026-07-20:** добавлен отдельный, намеренно
неактивированный WS auth v3 foundation: append-only protobuf messages/tags,
origin-bound one-shot challenge и private native account/device proof/result
helpers с явным existing/open/Pass intent. Живой `/ws` по-прежнему создаёт и
проверяет только legacy v2; canonical raw protobuf boundary, полный v3 verifier,
atomic Pass/account transaction, transport dispatch и двухнодовая relay-матрица
остаются blocking gates. Точные evidence и non-claims опубликованы в
[`docs/reviews/phase-5s-ws-auth-v3-foundation-checkpoint.md`](docs/reviews/phase-5s-ws-auth-v3-foundation-checkpoint.md).

**Local checkpoint 5S.3B-3 2026-07-20:** добавлен изолированный REST auth v2
foundation. Private native preparer использует системные clock/CSPRNG, строит
пять канонических header values и не имеет transport/FFI call site;
transport-neutral Go verifier принимает уже захваченные bounded target/body,
публикует principal только после strict Ed25519 proof и atomic replay claim.
PostgreSQL migration хранит replay по exact `(account, nonce)` с пятиминутным
retention и bounded expired-only cleanup, общими между процессами и restart.
Это не HTTP activation: raw `RequestURI`/body capture and restore, route media
policy, version dispatcher, desktop/Android transport, legacy cutover и real
two-Node matrix остаются открытыми, а Node Access Pass принадлежит только
будущему WS v3 registration verifier. Точный checkpoint:
[`docs/reviews/phase-5s-rest-auth-v2-foundation-checkpoint.md`](docs/reviews/phase-5s-rest-auth-v2-foundation-checkpoint.md).

**Local checkpoint 5S.3B-4 2026-07-20:** добавлены изолированный server WS auth
v3 verifier и атомарный PostgreSQL admission. One-shot challenge, exact
configured origin, account-signed active device binding, contributory
account/device DH и chained Ed25519 proofs проверяются до любой registration
policy или Pass lookup. Для новой identity account, device, immutable binding
state и расход Pass входят в одну транзакцию; exact existing identity выигрывает
до Pass и делает uncertain post-commit retry идемпотентным. Успех возвращает
opaque verified result с principal, protocol, origin и signed intent из той же
проверенной попытки. Repo-wide AST gate подтверждает отсутствие live
`CreateChallengeV3`/`VerifyResponseV3` callsite. Живой `/ws` всё ещё v2; raw
canonical protobuf, subprotocol/gateway dispatch, client consumption и реальная
двухнодовая relay-матрица остаются blocking gates. Точный checkpoint:
[`docs/reviews/phase-5s-ws-auth-v3-verifier-admission-checkpoint.md`](docs/reviews/phase-5s-ws-auth-v3-verifier-admission-checkpoint.md).

**Local checkpoint 5S.3B-5 2026-07-20:** добавлены изолированные REST auth v2
HTTP boundary и version dispatcher без live route. Boundary получает signed
target только из raw `RequestURI`, собирает все case-insensitive header values,
до body read выполняет canonical preflight/key lookup, затем один раз bounded
читает и точно восстанавливает body под общей v1/v2 admission authority.
Principal публикуется только после exact body signature, повторной freshness
проверки, 60-секундного monotonic staged-proof bound и durable replay winner.
Явный `not found` отделён от timeout/cancel/storage failure: первый даёт generic
401, неопределённость — generic 503. `V2Only` не допускает downgrade;
`PreviewDual` имеет owner, максимум 30 дней, monotonic deadline и sticky
fail-closed expiry без fallback. Это всё ещё не activation: route/media table,
ServeMux/redirect guard, bounded key-lookup concurrency, short absolute body
read deadline, telemetry/config wiring, desktop/Android transport и реальная
two-Node matrix остаются blocking gates. Точный checkpoint:
[`docs/reviews/phase-5s-rest-auth-v2-http-boundary-checkpoint.md`](docs/reviews/phase-5s-rest-auth-v2-http-boundary-checkpoint.md).

**Beta checkpoint 5S.3C 2026-08-04:** baseline `f6dbf5a` регистрирует отдельный
`/v3/events` в gateway и добавляет Rust supervisor, FFI controller и Android
background-service consumer. Legacy `/ws` остаётся отдельным v2 путём, REST v2
не активирован. Этот срез ещё не проходит полный workspace build, generated
Kotlin bindings отстают, а endpoint-level, cross-client и hostile two-Node
evidence отсутствуют. Поэтому checkpoint расширяет integration surface, но не
закрывает cross-Node P1, live cutover или Exit gate 5S. Точные blockers и
проверки записаны в
[`docs/reviews/beta-integration-macos-2026-08-04.md`](docs/reviews/beta-integration-macos-2026-08-04.md).

Private/E2EE keys при этом не извлекаются, но A может получить authenticated
control/metadata context на B и злоупотреблять server-authoritative actions,
receipts или availability. Единое обязательное исправление:

1. Node стартует только с явно configured canonical public origin; runtime не
   выводит trust scope из request `Host`. Gateway/TLS строго проверяют ожидаемые
   Host и SNI, не нормализуют чужой origin и не допускают origin-changing redirect.
2. Versioned `veil-ws-auth-v3` включает server-declared и client-verified canonical
   origin в challenge, account proof и device proof, а registration path — явный
   intent и domain-separated commitment B Pass без раскрытия Pass в подписи.
3. Versioned REST v2 подписывает как минимум exact canonical origin, `user_id`,
   method, canonical request target/body commitment, timestamp/nonce и protocol
   version. Server сравнивает подписанные origin/user с собственной конфигурацией
   и authenticated account; `X-Veil-User` не является отдельным источником доверия.
4. Missing/mismatched version/origin/user и downgrade отклоняются. Временный v1/v2
   dual-stack допустим только под явным Preview compatibility flag с конечным
   сроком; production принимает только WS v3 + REST v2. Обязательны two-Node relay,
   B-account/open-registration/B-Pass и Host/SNI/downgrade adversarial tests.

- first-contact identity/prekey substitution и equivocation, когда Node показывает
  разным клиентам разные ключи одного пользователя;
- stale/replayed prekeys, повторная выдача one-time prekey, forged key-change и
  device-roster события, rollback revision и удаление/reordering ciphertext;
- registration/pass abuse, selective denial of service и подмена canonical origin;
- сбор неизбежных transport metadata: IP, время/размер трафика, membership,
  conversation/Room routing и delivery state. E2EE не должна описываться как
  защита этих метаданных.

До security claim для Circle или Space требуется отдельная malicious-roster
boundary. Server-authoritative ACL/roster и Sender Key сами по себе не доказывают,
что все клиенты видят один и тот же авторизованный состав: злонамеренный Node не
может подделать account-signed device уже закреплённого честного аккаунта, но может
добавить свой новый легитимный account/device, показать разные roster views и
добиться раздачи следующего Sender Key этому участнику. Нужны monotonic signed
membership epochs с проверкой authorization, consistency и client
gossip/witnessing либо MLS application-authorization contract с эквивалентной
защитой от rollback/equivocation. Сам переход на MLS или `libsignal` эту product
authorization boundary автоматически не закрывает.

Минимальный пользовательский baseline: versioned safety number/fingerprint для
каждого account/device, QR/внеполосная проверка, заметное key-change событие и
fail-closed pause до подтверждения. Отдельный ADR выбирает проверяемую
key-transparency модель для self-hosted Node: append-only proofs, consistency
checks и client gossip/witnessing должны выявлять equivocation; подписи самого
злонамеренного Node без независимой проверки недостаточно.

Android обязан закрыть этот baseline реальным mobile flow: показать и сравнить
полный account/device fingerprint, поддержать QR show/scan и явно подтверждённую
внеполосную проверку, затем сохранить verification в SQLCipher по exact
`(canonical origin, local account, peer account/device, identity key)`. Restart
сохраняет proof, а любое key/device/origin change переводит его в blocking
`Identity changed` до нового сравнения; один лишь display fingerprint gate не
закрывает.

### Exit gate 5S

- принят ADR `Veil Direct v1 vs direct_v2_libsignal` с threat model и миграцией;
- exact protocol fixtures одинаково проходят desktop и Android;
- hostile-Node/two-client matrix доказывает отсутствие silent key replacement,
  plaintext fallback, state rollback и downgrade;
- configured canonical public origin, strict Host/SNI, `veil-ws-auth-v3` и REST v2
  exact-origin/user proofs проходят двухнодовую credential relay matrix, а
  production Node не принимает origin-unbound WS v2 или ingress-dependent REST v1;
- Android fingerprint compare/QR/persistence и key-change fail-closed matrix зелёны;
- Circle/Space membership epochs либо MLS authorization/consistency/gossip contract
  выдерживают malicious-Node roster equivocation/rollback matrix;
- независимый аудит завершён, а обязательные findings закрыты;
- документация честно разделяет confidentiality содержимого, authentication
  первого контакта, availability и metadata privacy.

До выполнения exit gate разрешены только явно помеченные Preview/internal builds.
MLS остаётся выключенным и не используется как обход незакрытого Direct review.

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
workflow уже есть. 2026-08-04 локально воспроизведены x86_64 `Veil.app` и DMG
0.1.4; DMG прошёл `hdiutil verify`, но app не подписан, не notarized и не имеет
arm64/universal варианта. Это development evidence, а не public artifact. Без
сертификата workflow не должен выпускать артефакт. Visual regression, updater,
полный signed matrix и public beta ещё не готовы.

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
  oriented web flow: будущий Secure Share Viewer с собственным ограниченным
  threat model и существующий unauthenticated allowlisted Veil Link preview.
  Ни один из них не становится web messenger и не получает account identity/
  session, recovery flow или keys. Наличие prototype `veil-share-viewer` не
  считается production surface до completion gate Phase 4G.

Компрометация сайта не должна позволять выдать изменённый клиент за Veil:
подпись приложения проверяется ОС, hashes/signing metadata дублируются в
GitHub release, а updater использует отдельную подписанную manifest chain.

### Локализация в конце разработки

Полная локализация выполняется в Phase 8, когда основная продуктовая IA
стабилизирована. Первый обязательный набор — `en` как canonical fallback и `ru`
как полноценно поддерживаемая локаль. Чтобы поздняя локализация не потребовала
переписывать протоколы, до Phase 8 сохраняются следующие правила:

- сервер возвращает стабильные machine-readable error/event codes, а клиенты
  сопоставляют их с append-only `PublicFailureCodeV1`; public codes, wire values,
  IDs, keys, origins и crypto labels не переводятся и не переиспользуются,
  локализуются только reviewed title/description/next-action keys;
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
4. CI проверяет missing/unused keys, variable parity, forbidden raw strings и
   полное покрытие `PublicFailureCodeV1` во всех локалях без изменения recovery
   semantics; pseudo-locale/long-text, `en`, `ru`, 125–200% scale и RTL/bidi
   isolation входят в component/visual/accessibility matrix.
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
