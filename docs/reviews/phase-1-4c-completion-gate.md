# Completion gate: Phase 1–4C

Дата: 2026-07-12

Статус: **пройден для начала Phase 4D foundation**. Gate не является заявлением
о production-ready релизе, завершённом Android-клиенте или независимом
криптографическом аудите.

## Решение по scope

Старые фазы смешивали готовый protocol/runtime с будущими продуктовыми
клиентами. Gate не скрывает незавершённую работу: она явно вынесена в отдельные
фазы и больше не является критерием завершения исходного core scope.

| Scope | Решение | Доказательство / следующий владелец |
|---|---|---|
| Phase 1, desktop composite UI | закрыт | Kobalte Dialog/Popover/Tabs/Portal, focus return, keyboard/ARIA tests; простые semantic buttons не требуют headless primitive |
| Phase 2, RAM-only search | закрыт | rebuild из SQLCipher, Tantivy `RamDirectory`, command-palette keyboard contract |
| Phase 3, encrypted upload core | закрыт | tus ACL, chunked AEAD v2, streaming/resume tests; desktop attachment UX и bounded 2 GiB streaming выделены в Phase 3B |
| Phase 4, push transport core | закрыт | encrypted wake-up envelope, subscription lifecycle и dispatcher; полноценные device `K_push` clients выделены в Phase 4P |
| Phase 4A, server access core | закрыт | authoritative channel ACL/overwrites, exact roster revisions, migrations и integration tests; продуктовый server IA/settings выделен в Phase 4E |
| Phase 4B, Windows desktop UX | закрыт | пять тем, local wallpaper, UI scale, PIN 6–12 + legacy unlock, contrast/focus, 800×600/1200×800/1440×900 visual matrix и Windows NSIS bundle |
| Phase 4C, Sender Keys v5 baseline | закрыт | exact-device bindings/roster, immutable multi-generation retention, durable exact receipts, atomic scoped recovery and quarantine; ADR-0001 остаётся каноническим |

## Проверки gate

- `cargo fmt --all -- --check` — успешно.
- `cargo clippy --workspace --all-targets -- -D warnings` — успешно на чистом
  target.
- `cargo test --workspace --all-targets` — успешно: client, crypto, desktop,
  SQLCipher store, uploads, MLS, FFI и search.
- Chunked AEAD v2 включает injectivity/boundary regression; legacy v1 collision
  воспроизводится тестом и не имеет fallback в v2.
- `go test ./...`, `go vet ./...` и Docker integration suite с migrations/ACL/
  permission linearization — успешно.
- `pnpm test:run` — 18/18; `pnpm build` — успешно.
- Playwright — 17 passed, 4 ожидаемых project skips: wallpaper send/scroll,
  composer geometry, members breakpoint, five-theme contrast и LockScreen на
  800×600/640×480 (125%-equivalent).
- Windows release: unsigned NSIS bundle собран успешно. На текущем toolchain
  OpenSSL/nmake требует ASCII `CARGO_TARGET_DIR`; кириллица в release target
  воспроизводимо ломает upstream build, поэтому release workflow обязан задавать
  отдельный ASCII target path.
- Локальное обновление проверено на реальной БД: gateway был остановлен, сделан
  и проверен custom-format `pg_dump`, migrations 011–019 применены, ledger
  содержит 001–019, новый gateway отвечает `/health` 200, native release запущен.

## Закрытые security-хвосты

- Operational logs используют краткоживущие HMAC refs вместо raw account,
  device, conversation, message, file и endpoint identifiers.
- Runtime error logs содержат bounded `error_class`, а не DB/path/URL details.
- Единый `publicerr` fail-closed boundary исключает внутренние SQL, crypto,
  filesystem и URL errors из HTTP/WS/tusd 5xx ответов; AST regression запрещает
  возврат `.Error()` через transport boundary.
- Deep links и destructive actions больше не используют browser
  `confirm/prompt/alert`: решения проходят через focus-trapped in-app queue.
- Удалены неиспользуемые параллельные desktop `ChatIsland`, `NewDmDialog` и
  backup-router path.

## Остаточные риски, не скрытые этим gate

1. Device/account binding пока опирается на service-mediated TOFU: key
   transparency и независимая верификация не реализованы. Phase 4D обязана
   показывать это честно и не называть TOFU состоянием `Verified`.
2. Есть per-conversation cap для retained Sender-Key generations, но глобальный
   storage budget/compaction policy остаётся release hardening (Phase 8).
3. Автоматизированы exact-device/offline/race сценарии, но ручная двухмашинная
   desktop↔desktop матрица и Android device matrix ещё не выполнены.
4. `AuthResult` содержит безопасное фиксированное сообщение, но пока не имеет
   отдельного machine-readable error code.
5. NSIS bundle не подписан; code signing, SmartScreen reputation, SBOM,
   reproducible release и независимый security review остаются Phase 8.
6. Frontend production chunk превышает 500 KiB warning threshold; это
   performance/decomposition tail, не security bypass.

## Разрешение для Phase 4D

Разрешено начинать только с `ProfileLocator`, origin-scoped identity directory,
persisted author metadata, Phaseprint и общего `UserAvatar`. Presentation
metadata не участвует в crypto trust, ACL или Sender-Key rotation. Network text
profile и особенно avatar ingest нельзя включать до отдельных schema/API,
privacy и image-decoder tests, перечисленных в Phase 4D.
