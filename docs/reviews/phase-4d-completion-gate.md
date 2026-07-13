# Completion gate: Phase 4D

Дата: 2026-07-13

Статус: **финальная матрица выполняется**. Продуктовый и security scope
реализован, code-review freeze пройден, но Phase 4D не объявляется
закрытой до зелёной full-workspace, Docker, visual, migration, Windows
native/release матрицы. Документ будет обновлён фактическими
результатами перед финальным решением.

Gate не является заявлением о production-ready релизе, key transparency,
завершённом Android runtime или независимом криптографическом аудите.

## Решение по scope

| Deliverable | Статус | Инвариант |
|---|---|---|
| Canonical identity foundation | реализован | locator включает canonical origin, user ID, X25519 identity key и Ed25519 signing key; conversation ID не используется как peer user ID |
| Durable identity directory and authors | реализован | SQLCipher хранит origin-scoped account snapshots, immutable message-author metadata и current/former-member context; restart не заменяет автора префиксом ключа |
| Phaseprint and `UserAvatar` | реализован | deterministic identity-key-first seed, origin-scoped fallback, nickname-independent rendering, safe fallback on image failure |
| Identity Island | реализован | one Members ↔ Identity route, wide island and focus-trapped narrow sheet, Person/Context/Identity Proof, keyboard-safe triggers and return focus |
| Versioned text profile | реализован | signed same-origin API, bounded NFC plain text, CAS revision, relationship-scoped presentation event; profile data never changes trust, ACL or key rotation |
| Local identity proof | реализован | full account-v2 fingerprint is compared out of band; TOFU remains `Not compared`; changed keys durably block the exact account until a new explicit comparison |
| Isolated avatar pipeline | реализован | signed self-only PNG/JPEG ingest, bounded decode/normalize/re-encode, metadata stripping, opaque asset ID, native same-origin fetch, renderer-local `blob:` only |
| Mobile adaptation | реализован как 5A UI foundation | shared Phaseprint semantics and modal bottom sheet; production network/runtime integration remains Phase 5A/5B |

## Границы доверия

- Display name, about, avatar, nickname, role and presence не участвуют в crypto
  trust, verification, ACL, Sender-Key roster или rotation.
- Profile text/avatar видны оператору выбранного origin и честно помечены
  как не-E2EE metadata.
- Renderer не доверяет TypeScript declarations на IPC boundary: message,
  live-event и search DTO проходят runtime schema, budget, canonical origin,
  UUID, key, revision and authenticated-generation checks.
- Canonical Ed25519 public keys проверяются как non-identity points полной
  prime-order subgroup на server admission/storage, client SQLCipher/self-binding и FFI
  fingerprint boundaries. Small-order, mixed-torsion and non-canonical encodings fail closed.
- Active authenticated history до любой decryption/device-proof mutation сверяет
  user/identity/signing tuple со всеми durable account/self owners. Alias пишет
  alarm на UUID авторитетного владельца и не продвигает candidate.
- Ciphertext formats, Double Ratchet, authenticated Sender Keys v5, channel ACL and
  rotation contract в Phase 4D не ослаблялись. Silent plaintext/weak-crypto fallback
  отсутствует.

## Найдено и закрыто во время финального review

1. Server/client Ed25519 admission допускал weak-point registration. Добавлен
   единый strict prime-order validator и startup preflight уже сохранённых keys.
2. Early historical alarm сначала сравнивал только тот же user UUID.
   Owner-aware alias/self classifier теперь выполняется до crypto early-return;
   alarm атомарен и candidate не попадает в directory.
3. Native-to-renderer identity-bearing DTO не имели полной runtime validation.
   Добавлены fail-closed message/live/search validators и exact scope capture.
4. Wide Members/Identity transition мог сделать active element inert до
   focus handoff. Focus теперь уходит до route/visibility mutation, transfer
   подтверждается через `activeElement`; есть fallback при удалённом member.
   Proof показывает full-scheme origin, long text bounded, desktop/mobile a11y дополнена.

Независимые read-only re-review не нашли оставшихся P0/P1 в исправленном
cryptographic admission/continuity scope. Финальный UI/UX/a11y/animation
re-review также закрыт без P0/P1/P2; последний connected-but-inert focus-return
сценарий покрыт regression-тестом.

## Промежуточные evidence

- `cargo fmt --all -- --check` — успешно.
- Strict Ed25519 tests — 3/3; SQLCipher store — 60/60 до последней alias
  regression; historical owner/self — 2/2; desktop early-history — 1/1.
- Desktop `tsc --noEmit` и полный `pnpm test:run` после последней focus
  regression — 19 files, 100/100.
- Mobile `tsc --noEmit` и Jest — 5 suites, 18/18.
- Go unit/vet/race и Docker weak-key/profile integration были зелёными на
  code-review freeze; они будут повторены в финальной матрице.

## Обязательные оставшиеся шаги gate

- workspace `clippy -D warnings` и all-targets tests;
- final `go test ./...`, `go vet ./...` и Docker integration suite;
- desktop production build и visual/a11y matrix;
- local PostgreSQL backup, migrations 020–022 ledger and gateway/profile health smoke;
- Windows native release/smoke и final NSIS из ASCII target, с SHA-256 evidence;
- финальный clean-diff/status review, commit и push.

## Остаточные риски, не скрытые Phase 4D

1. Account/device discovery остаётся service-mediated TOFU; key transparency
   и независимый transparency log отсутствуют.
2. Глобальный Sender-Key storage budget/compaction остаётся Phase 8 hardening.
3. Ручная физическая multi-device matrix остаётся Phase 4E/release evidence.
4. `AuthResult` пока без отдельного machine-readable error code.
5. Windows NSIS не подписан; signing, SmartScreen reputation, SBOM и
   reproducible release остаются Phase 8.
6. Mobile пока не production messaging client; это Phase 5A/5B, а не хвост Phase 4D.
