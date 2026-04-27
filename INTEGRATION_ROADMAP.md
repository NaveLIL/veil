# Дорожная карта

Восемь фаз интеграции. Из которых пять реально сделаны. Остальные — заметки на будущее, в той степени как я их обдумывал.

Порядок выполнения сложился как: 1 → 2 → 4 → 3 (idея с tus пришла позже) → 4A → search/UI. Дальше нужны звонки (7), мобильный UI (5) и MLS (6) — хотя MLS это отдельный большой кусок работы с высоким риском.

## Статус по фазам

| # | Фаза | |
|---|------|--|
| 1 | Kobalte — headless UI | готово |
| 2 | Tantivy — локальный поиск | готово |
| 3 | tus.io — загрузка файлов | сервер + Rust, UI отложен |
| 4 | UnifiedPush / ntfy | сервер готов, мобильный клиент отложен |
| 4A | Группы, серверы, роли | готово |
| 5 | Мобильный UI | не начато |
| 6 | OpenMLS | в работе (фундамент готов) |
| 7 | LiveKit звонки | не начато |
| 8 | Полировка, релиз | не начато |

---

## Phase 1 — Kobalte

Заменил self-rolled Dialog/Select/ContextMenu/Tooltip на Kobalte primitives. Смысл: a11y (focus trap, ARIA, клавиатурная навигация) бесплатно, не меняя визуал. Только `@kobalte/core` (unstyled) — не `@kobalte/elements`.

Что сделал:
- `IslandDialog`, `IslandSelect`, `tooltip`, `context-menu` переписаны на Kobalte
- Добавил Toast (вместо красных полос), Switch (настройки), Sheet (slide-in панели), базовый Combobox
- Portal монтируется в `#island-portal` — иначе blur/backdrop рвётся в Tauri frameless режиме
- z-index вынес в `src/lib/zIndex.ts` (Z_DIALOG=50, Z_DROPDOWN=60, Z_TOAST=70, Z_DRAG=80). Больше никаких `z-50` напрямую в классах

Что поймал в процессе:
- Kobalte восстанавливает focus только если trigger рендерится через `Dialog.Trigger`. Там, где я открываю диалог через `setOpen(true)` из произвольных обработчиков, нужно переписать — обернуть в `Trigger`
- Drag-handle внутри диалога + focus trap: Kobalte поглощает pointerdown на тайтлбаре. Решение — `data-kb-focus-trap-exception` на ручку
- Tooltip на тачскрине: спецификация Kobalte его игнорирует. Нужен long-press fallback через `@solid-primitives/event-listener` — пока не сделано

Итог: `pnpm build` зелёный, 404 КБ JS, 54 КБ CSS.

---

## Phase 2 — Tantivy локальный поиск

Полнотекстовый поиск по расшифрованным сообщениям. Индекс живёт только на устройстве, на сервер ничего не уходит. Поисковый трафик сервер не видит вообще.

Схема индекса: `id (STORED)`, `conversation_id (STORED + INDEXED)`, `sender_id (STORED + INDEXED)`, `body (TEXT)`, `timestamp (STORED + FAST для сортировки)`. Токенайзер — стандартный с lowercaser. Для кириллицы в v1 нормально. Потом можно будет прикрутить tantivy-tokenizer-api для multi-language.

Tauri команды: `search_messages`, `rebuild_search_index`, `clear_search_index`, `ensure_search_backfill`.

Backfill: при первом запуске запускается async, не блокирует UI, идемпотентен через marker-файл `<index_dir>/.backfilled`.

Что надо помнить:
- Ротация ratchet ключей не требует реиндексации — plaintext не меняется, это важно задокументировать
- При удалении сообщения надо вызывать `Indexer::delete(id)` — сделано
- Tantivy занимает ~30% от размера plaintext. Для активных пользователей заметно, надо будет добавить настройку лимита с LRU эвикцией по старым сегментам
- Индекс содержит plaintext на диске. На Linux/macOS хватает прав ФС, на Windows нужно явно ACL директорию
- Смена схемы = полный ребилд. Директории `search/v1/`, `search/v2/` решают проблему — при апгрейде старый индекс просто игнорируется, ребилд стартует

Что сделано: crate `veil-search`, подключён в `veil-client::api` в шести местах (outgoing + incoming: insert, edit, delete). UI: `CommandPalette` на Kobalte Dialog + Cmd/Ctrl+K, debounce, inline `<mark>` highlight, клавиатурная навигация.

---

## Phase 3 — tus.io загрузка файлов

Цель: файлы до 2 ГБ, resumable, клиент шифрует до отправки. Сервер хранит только ciphertext-блобы.

**Как отличается от изначальных планов:**

tusd внутри gateway, не в отдельном бинарнике `cmd/uploads/`. Одна точка входа, один auth surface, проще в ops. Разнести можно потом без изменений протокола.

Auth через bearer-token, не через X-Veil подпись на каждый PATCH. Причина: X-Veil подписывает `sha256(body)`, а для стриминговой загрузки хешировать весь чанк тела убивает смысл tus. Клиент делает `POST /v1/uploads/token` (X-Veil подпись), получает HMAC-SHA256 bearer (`v1.<user>.<expires>.<mac>`), по умолчанию TTL 24 ч (`UPLOAD_TOKEN_TTL`). При долгом resume — минтим новый токен и продолжаем.

Quota gate в `pre-create` через `db.SumTusBytesInWindow` за скользящие 24 ч. HTTP 413 до того как что-то легло на диск — нельзя сжечь квоту незавершёнными загрузками.

Crate `veil-uploads` поверх `veil_crypto::chunked_aead`. Конструкция chunks: nonce = `(nonce_prefix || u64_be(chunk_index))`, AAD = `(nonce_prefix, chunk_index, is_final)`. Детектирует переставку чанков, обрезание, замену. Каждый чанк аутентифицирован отдельно.

Sweeper: горутина раз в `UPLOAD_SWEEP_INTERVAL` (1 ч по умолчанию) убивает просроченные блобы через tusd's Terminater + дропает строки. Abort TTL = `UPLOAD_ABORT_TTL` (24 ч), retention завершённых = `UPLOAD_RETENTION` (30 дней).

Download: `GET /v1/uploads/blob/{file_id}` — свой эндпоинт с auth проверкой. В v1 только uploader скачивает; в Phase 6 расширится на участников разговора через MLS.

**Что отложено:**
- Tauri команды + drag-drop UI + file bubble компонент
- EXIF strip (клиентская сторона, до шифрования; `kamadak-exif` или ре-энкод через `image`)
- `veilfile://` custom protocol для range-decrypt видео в `<video>` теге
- K-wrapping для больших групп (зависит от Phase 6 MLS)
- Streaming uploader API (сейчас `encrypt_file_to_chunks` материализует весь список чанков в памяти; нужен async stream когда начнём пушить 2 ГБ видео)

Важные грабли, которые надо помнить:
- MIME spoofing: не доверять client-declared MIME. Ре-деривить на стороне получателя через `infer` crate перед рендером
- Resume после долгого оффлайна с другим IP: bearer-токен привязан к пользователю, не IP. Достаточно заминтить новый токен
- Disk fill от прерванных загрузок: `unfinished-upload-expiration` в tusd = 24 ч (UPLOAD_ABORT_TTL)
- Per-recipient K в группах: не шифровать файл 50 раз для 50 человек. Шифруем один раз, потом K оборачиваем для всех в одном MLS commit (Phase 6)

---

## Phase 4 — UnifiedPush / ntfy push-уведомления

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

**Pending (мобильная сторона):**
- Android: `react-native-unifiedpush-connector` в `veil-mobile/`, distributor picker, notification listener с K_push из keychain
- iOS: ntfy iOS app как APNS bridge, App Group для shared keychain между extension и основным приложением
- Desktop: settings panel с list/add/delete subscriptions (Tauri команды + Kobalte Dialog)

Грабли:
- iOS App Group keychain: main app + extension обязаны использовать один access group. Без этого extension не расшифрует и будет вечно показывать "New message"
- Stale endpoints: ntfy может вернуть 410. Dispatcher ловит и прунит строку — это сделано
- Replay: в envelope есть `msg_id` + monotonic counter per-subscription для дедупликации
- Mute/DND должны проверяться на сервере (не отправлять push) — пока не реализовано

---

## Phase 5 — Mobile UI

NativeWind v4 + React Native Reusables. Цель: feature-parity с desktop, тот же Island-стиль, нативные жесты.

Shared tailwind конфиг: `tailwind.config.shared.js` в корне репо, оба проекта импортируют из него палитру и radii. Единый источник правды для цветов.

`veil-mobile/src/components/ui/` зеркалит структуру `veil-desktop/src/components/ui/`:
- `IslandView` ↔ `Island.tsx`
- `IslandSheet` ↔ `IslandDialog.tsx` (на мобиле — bottom sheet)
- `IslandSelect`, `IslandTextInput`, `IslandButton` и т.д.

Стейт: `veil-desktop/src/stores/` → `packages/veil-shared-state/` (pnpm workspace). Desktop adapter: `@tauri-apps/api`. Mobile adapter: `expo-secure-store` + NativeModule bridge. Абстракция `Platform { invoke, listen, secureStore }`.

Что будет больно:
- NativeWind v4 — свежий, Metro bundler иногда глючит. Пинить версию
- iOS keychain + Rust: `react-native-keychain` с biometric gate
- Reanimated worklets не могут читать store напрямую. `useAnimatedReaction` как мост — легко накосячить, профилировать на реальном устройстве
- State sync между push extension и основным приложением: shared SQLite в WAL mode + refresh при foreground
- Android back button: надо проводить через navigation stack даже с Expo Router — сначала закрывает sheet/dialog, потом навигирует

---

## Phase 6 — OpenMLS

Заменить `ratchet.rs` (DM) и `sender_key.rs` (маленькие группы) на [OpenMLS](https://github.com/openmls/openmls) (RFC 9420). Post-compromise security, forward secrecy при kick.

Гибридная стратегия: MLS для 2–500 участников, Sender Keys для 500+. Хранится в `conversations.crypto_mode`. Обе crypto-стеки живут бесконечно — разные инструменты для разных масштабов.

Почему не MLS везде: каждый Commit должен обработать каждый член. На 1000 участников при активном churn — CPU bottleneck на клиентах. Wire/Webex деплоят MLS в сотнях, не тысячах. Для 10k+ каналов Sender Keys (Signal-style) остаётся.

Cipher suite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Один, не менять.

Migration plan:
1. `crypto_mode` DEFAULT `'sender_key'` — старые группы не трогаем
2. Новые DM/маленькие группы = MLS, если клиент поддерживает (capability flag в профиле)
3. Кнопка "Upgrade to MLS" в настройках группы + system message "шифрование обновлено"
4. `ratchet.rs` deprecated для новых разговоров через 2 релиза, код остаётся навсегда для старых данных

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

### Что осталось

- HTTP-клиент в `veil-client` для подписанных REST-запросов к `/v1/mls/*` (сейчас клиент целиком работает поверх WS protobuf).
- Адаптер `MlsKeyStore` поверх `VeilDb` (сохранение `SignatureKeyPair` в SQLCipher).
- Ветвление `send_text`/`receive` в `veil-client/src/api.rs` по `crypto_mode` разговора.
- Tauri-команды `mls_create_group`, `mls_add_member`, `mls_upgrade_group` + UI-индикатор «MLS active» и кнопка «Upgrade to MLS» в настройках группы.
- Полноценный WS-канал `mls.welcome`/`mls.commit` (новый вариант `pb.Envelope`) вместо текущего log-стаба.
- Интеграционные тесты: catch-up Charlie оффлайн, авто-пополнение KP при count < 10, упорядоченное применение commits на трёх устройствах.

---

## Phase 7 — LiveKit звонки

1:1 + групповые войс-румы. E2EE через LiveKit insertable streams, ключи деривируются из MLS exporter secret (или sender-key chain) с меткой `"livekit-call-v1"`.

SFU видит только encrypted RTP. Ротация ключей при kick — нужно успеть до следующего фрейма, иначе отрезанный участник всё ещё слышит. Цель — < 1 RTT.

Desktop: `livekit-client` (npm), WebRTC в webview работает с `webrtc` фичей в `tauri.conf.json`.  
Mobile: `@livekit/react-native-client`. Android нужен foreground service для ongoing call. iOS — `AVAudioSession` config.

UI: Island-стиль, floating draggable CallView, те же материалы что и диалоги. Incoming call — toast с Accept/Decline. В группе — participant grid с glow-ring по амплитуде.

Compose: `livekit` + `coturn` (для ~10% за NAT). Codec: Opus + VP8. H.264 не трогать — patent surface и неровная поддержка в Tauri webview.

---

## Phase 8 — Полировка и релиз

- Grafana dashboard для метрик фаз 2-7, JSON в `grafana-dashboards/`
- Playwright visual regression baseline, запускается в CI на каждом PR
- Desktop: AppImage (Linux), .dmg (macOS), .msi (Windows) через `tauri build`
- Mobile Android: AAB через `eas build --platform android --profile production`
- Signed releases + Tauri updater (Ed25519)
- SECURITY.md: поддерживаемые версии, disclosure policy, threat model

---

## Открытые вопросы

- P2: шифровать ли Tantivy index на диске? → пока нет, отложено на v2
- P5: Expo Router сразу или после feature-parity? → сразу, потом мигрировать больно
- P6: именование leaf per-device → `user_id::device_label`, blake3-хеш в credential identity field
- P7: свой coturn или внешний? → свой в compose, ради приватности
- P8: code signing certs (macOS/Windows) → нужны до public beta, отдельный бюджетный вопрос
