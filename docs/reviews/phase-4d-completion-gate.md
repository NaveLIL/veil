# Completion gate: Phase 4D

Дата: 2026-07-13

Статус: **PASSED — Phase 4D закрыта**. Продуктовый и security scope
реализован, независимый code-review freeze пройден, full-workspace,
Docker, visual, migration и Windows native/release матрицы зелёные.
Release evidence собран из commit `6718595`.

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
5. REST replay nonce первоначально зависел от текстового Base64 signature.
   Strict Base64 decode отклоняет non-zero padding bits, а nonce строится из
   canonical decoded signature; padding-bit alias покрыт regression-тестом.

Независимые read-only re-review не нашли оставшихся P0/P1 в исправленном
cryptographic admission/continuity scope. Финальный UI/UX/a11y/animation
re-review также закрыт без P0/P1/P2; последний connected-but-inert focus-return
сценарий покрыт regression-тестом.

## Финальные evidence

- `git diff --check` и `cargo fmt --all -- --check` — успешно.
- `cargo clippy --workspace --all-targets -- -D warnings` — успешно.
- `cargo test --workspace --all-targets` — 297 passed, 0 failed,
  11 explicitly ignored superseded Sender-Key tests; exact-device replacements
  входят в зелёный набор.
- `go test ./...` и `go vet ./...` — успешно.
- `go test -count=1 -tags=integration ./internal/...` и канонический CI
  `go test -tags=integration -timeout 5m -v ./internal/integration/...` — успешно
  на одноразовых PostgreSQL 16 testcontainers. Fresh migration chain 001–022,
  weak-key startup preflight, signed profile/avatar lifecycle, global orphan
  budget, relationship-scoped event fanout и security/ACL/device matrix прошли.
- Desktop `tsc --noEmit`, `pnpm test:run` — 19 files, 100/100;
  `pnpm build` — 2108 modules; `pnpm test:visual` — 20 passed и 4 declared skip.
- Mobile Expo SDK 53 dependencies выровнены; `pnpm lint`, `tsc --noEmit`,
  `expo install --check`, public Expo config и sequential Jest — успешно,
  5 suites, 18/18.
- Перед локальными миграциями gateway-writer остановлен. Custom-format backup
  `backups/veil-pre-021-022-20260713-232008.dump` проверен через
  `pg_restore --list`: 178579 bytes, SHA-256
  `17B388FC4BB6C614CE5AB99B2F3DF38BEDC34FEC4AD2D98BF7F26ED5066103F4`.
  Ledger 001–020 сохранён, 021–022 применены; ownership FK/triggers/indexes
  проверены, 8 accounts и 11 conversations сохранены.
- Gateway пересобран из текущего source, startup cryptographic-key preflight
  прошёл, PostgreSQL healthy, `GET /health` возвращает 200, unsigned profile
  boundary — 401. Gateway, PostgreSQL и bundled ntfy имеют
  `restart: unless-stopped`.
- Windows release собран в ASCII target `D:\veil-release-target`.
  `veil-desktop.exe`: 35826688 bytes, PE subsystem 2, SHA-256
  `294231D15987C19E8BFDE6345F465F390D45E677DEAB1AE350509617F25F1AC4`.
  Изолированный native smoke создал responsive `Veil Desktop` window и
  завершился без раннего crash или console subsystem.
- Финальный NSIS:
  `D:\veil-release-target\release\bundle\nsis\Veil_0.1.0_x64-setup.exe`,
  13980337 bytes, PE subsystem 2, SHA-256
  `E9C3504BA5A095B7EB289CCDC0114BF6DF95D10F5076286B508DFA835DCA7367`.

## Решение gate

Phase 4D completion criteria выполнены. Следующая продуктовая работа может
переходить к Phase 4E/5A только как новый scope. Это решение не снимает
перечисленные ниже release и protocol risks и не объявляет Veil production-ready.

## Остаточные риски, не скрытые Phase 4D

1. Account/device discovery остаётся service-mediated TOFU; key transparency
   и независимый transparency log отсутствуют. Это отдельный pre-production
   protocol/security gate, а не незакрытая часть Phase 4D.
2. Глобальный Sender-Key storage budget/compaction остаётся Phase 8 hardening.
3. Ручная физическая multi-device matrix остаётся Phase 4E/release evidence.
4. `AuthResult` пока без отдельного machine-readable error code.
5. Windows NSIS не подписан; signing, SmartScreen reputation, SBOM и
   reproducible release остаются Phase 8.
6. Mobile пока не production messaging client; это Phase 5A/5B, а не хвост Phase 4D.
7. Desktop production bundle содержит один JS chunk 610.36 kB и получает
   non-blocking Vite size warning; code splitting остаётся Phase 8 performance work.
