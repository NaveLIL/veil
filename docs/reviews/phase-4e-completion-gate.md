# Phase 4E — completion gate

Дата проверки: 2026-07-14
Ветка: `codex/phase-4b-4c`

## Вердикт

Implementation и автоматизированный gate Phase 4E пройдены. Формальный статус
фазы остаётся `manual evidence pending`, пока не выполнена физическая
desktop↔desktop матрица на двух отдельных устройствах. Этот пункт нельзя
объявлять зелёным по эмуляции или двум процессам на одном Windows-хосте.

Криптографический протокол сообщений не менялся: Direct продолжает использовать
Double Ratchet, Circle и каждый Text Room — отдельный Sender Keys v5 domain.
Silent plaintext fallback, новый trust signal и параллельная ACL-модель не
добавлялись.

## Реализованный контракт

- Одна origin/binding-scoped `WorkspaceRoute` различает Home, Direct, Circle,
  Space и Room; одинаковые UUID разных Veil Nodes не смешиваются.
- Левый остров содержит Home, Circles, Spaces и одну кнопку создания. Старые
  параллельные create/join и DM/Group tabs удалены.
- Circle создаётся только с точными `(user_id, identity_key)` locators; creator и
  выбранные участники фиксируются одной PostgreSQL-транзакцией.
- Space показывает только реально поддерживаемые Text Rooms и Categories.
  Voice Room до Phase 7 не создаётся ни через UI, ни через API.
- Room access имеет честные режимы `Space-wide` и `Restricted`, построенные на
  существующих authoritative overwrites. Presentation metadata не участвует в
  ACL, trust или Sender-Key rotation.
- Ban/unban имеет signed API, authoritative persistence и атомарно удаляет
  участника из Space/Room rosters.
- Space использует декоративный deterministic mark из canonical origin + Space
  ID. Legacy `icon_url` удалён из migration 023, REST/native/renderer его не
  принимают и не публикуют.
- Veil Link v1 использует независимые 256-bit selector и secret,
  domain-separated SHA-256 secret storage, bounded lifetime/uses, revoke,
  revoke-all, bounded lifecycle journal и отдельные preview/join rate limits.
- Public portal не получает account session или IPC, не делает third-party
  requests и выставляет `no-store`, `no-referrer`, `nosniff`, `noindex` и CSP.
- Incoming capability разбирается authoritative native parser; renderer видит
  только origin, short selector reference и TTL. Pending secret хранится только
  process-local, очищается при lock/reset/cancel/timeout/success/origin mismatch.

Подробный wire/schema/privacy анализ:
[`phase-4e-veil-link-schema-security-review.md`](phase-4e-veil-link-schema-security-review.md).

## Автоматизированная матрица

| Проверка | Результат |
|---|---|
| `git diff --check` | PASS |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --all-targets` | PASS |
| `go test ./...` | PASS |
| `go vet ./...` | PASS |
| `go test -tags=integration -timeout 15m ./internal/integration/...` | PASS, 112.111s |
| `pnpm test:run` | PASS, 20 files / 109 tests |
| `pnpm build` | PASS |
| `pnpm test:visual` | PASS, 26 passed / 4 expected viewport skips |
| Windows Rust release check, ASCII target | PASS |
| Docker gateway rebuild + `GET /health` | PASS, HTTP 200 |

Integration отдельно подтвердил upgrade/fresh migration 023, полный hard cut
старых plaintext invites и `icon_url`, max-use race/idempotence, revoke-all,
ban/rejoin/unban, generic public responses/headers, atomic Circle creation и
отказ Voice Room до появления runtime.

## Ручная физическая матрица — обязательна до формального CLOSED

На двух разных desktop-устройствах и двух аккаунтах необходимо подтвердить:

1. Create Space → create Veil Link → открыть портал → native preview → explicit Join.
2. Отправка в Space-wide Room в обе стороны после exact-device distribution/ACK.
3. Перевод Room в Restricted, потеря/возврат доступа и отсутствие отправки при
   quarantine/rotation pending.
4. Revoke/revoke-all, expiry и max-use отказ без изменения roster.
5. Ban удаляет участника, блокирует повторный join; unban разрешает новый Link.
6. Lock/restart/cancel/origin mismatch очищают pending Link, а raw secret не
   появляется в renderer console, persistent files или access logs.
7. Keyboard/focus/reduced-motion поведение Members/Identity и узкого sheet.

До выполнения этих пунктов документация не использует формулировку `Phase 4E
closed`. Installer собирается на общем финальном gate, а не на этом checkpoint.
