# Документация Veil

Этот каталог содержит архитектурные решения, эксплуатационные инструкции и
evidence для completion gates. Veil остаётся pre-release проектом без
независимого криптографического аудита и стабильных compatibility guarantees.

## Начать отсюда

- [Краткая архитектура](architecture.md) — компоненты, trust boundaries и
  основные потоки данных.
- [Русская entry page](../README.md) — состояние продукта, локальный запуск и
  release process.
- [English entry page](../README.en.md) — compact project overview.
- [Участие в разработке](../CONTRIBUTING.md) — workflow, проверки и
  лицензионные условия вклада.
- [Security Policy](../SECURITY.md) — приватное сообщение об уязвимостях.
- [Поддержка](../SUPPORT.md) — выбор канала и безопасная диагностика.

## Architecture Decision Records

- [ADR-0001: Authenticated Sender Keys v5 for server channels](adr/0001-authenticated-sender-keys-v5-for-server-channels.md)
- [ADR-0002: Origin-bound one-time Node Access Passes](adr/0002-origin-bound-node-access-passes.md)
- [ADR-0003: Origin-bound transport authentication](adr/0003-origin-bound-transport-authentication.md)
- [ADR-0004: Clean Slate v0.3 and open-source protocol preference](adr/0004-clean-slate-v0.3-and-open-source-crypto.md)
- [ADR: Witnessed key transparency and authorized membership epochs](adr/0002-witnessed-key-transparency-and-membership-epochs.md)

ADR фиксирует принятое решение и причины. Изменение такого решения должно
добавлять новый ADR, а не незаметно переписывать исторический документ.

## Operations

- [Cryptographic identity rotation](operations/cryptographic-identity-rotation.md)
- [Sender-Key device-routing cutover](operations/sender-key-device-routing-cutover.md)
- [Identity transparency witness rollout](operations/transparency-witness-rollout.md)
- [Production deployment](../deploy/README.md)

Операционные инструкции не заменяют backup, rollback и smoke gate конкретного
развёртывания. Секреты и production-значения не должны попадать в документацию.

## Product/security contracts

- [Node administration, moderation and reports](product/node-administration-and-reports.md)
- [Secure Share for guests](product/secure-share-for-guests.md)

Эти документы фиксируют planned boundaries и completion criteria. Наличие
контракта или prototype-модуля не означает, что функция доступна в Preview.
После принятия wire/storage решения оно дополнительно фиксируется ADR.

## Reviews и completion gates

- [Security hardening audit handoff — 2026-08-05](reviews/security-hardening-audit-handoff-2026-08-05.md)
- [Security hardening checkpoint — 2026-08-04](reviews/security-hardening-checkpoint-2026-08-04.md)
- [Beta integration and macOS checkpoint — 2026-08-04](reviews/beta-integration-macos-2026-08-04.md)
- [Phase 1–4C completion gate](reviews/phase-1-4c-completion-gate.md)
- [Phase 2 search product gate](reviews/phase-2-search-product-gate.md)
- [Phase 3B attachment security review](reviews/phase-3b-attachment-security-review.md)
- [Phase 4D avatar security review](reviews/phase-4d-avatar-security-review.md)
- [Phase 4D completion gate](reviews/phase-4d-completion-gate.md)
- [Phase 4D text profile security review](reviews/phase-4d-text-profile-security-review.md)
- [Phase 4E completion gate](reviews/phase-4e-completion-gate.md)
- [Phase 4E Veil Link schema/security review](reviews/phase-4e-veil-link-schema-security-review.md)
- [Phase 4P device push client review](reviews/phase-4p-device-push-client-review.md)
- [Android runtime terminal failure review](reviews/android-runtime-terminal-failure-review.md)
- [Android identity setup reconciliation review](reviews/android-identity-setup-reconciliation-review.md)
- [Android Direct public-failure action contract](reviews/android-direct-public-failure-action-contract.md)
- [Android native contacts and Direct initiation contract](reviews/android-native-contacts-direct-initiation-contract.md)
- [Android tester artifact contract](reviews/android-tester-artifact-contract.md)
- [Android Direct Preview physical test plan](reviews/android-direct-preview-physical-test-plan.md)
- [Phase 5S Direct-v1 transcript checkpoint](reviews/phase-5s-direct-v1-transcript-checkpoint.md)
- [Phase 5S Direct-v1 key-validation checkpoint](reviews/phase-5s-direct-v1-key-validation-checkpoint.md)
- [Phase 5S Direct-v1 skipped-key/state checkpoint](reviews/phase-5s-direct-v1-skipped-key-state-checkpoint.md)
- [Phase 5S isolated libsignal source/build spike](reviews/phase-5s-libsignal-isolated-spike.md)
- [Phase 5S exact-origin transport-auth contract checkpoint](reviews/phase-5s-hostile-node-auth-contract-checkpoint.md)
- [Phase 5S configured-origin foundation checkpoint](reviews/phase-5s-configured-origin-foundation-checkpoint.md)
- [Phase 5S WebSocket auth v3 foundation checkpoint](reviews/phase-5s-ws-auth-v3-foundation-checkpoint.md)
- [Phase 5S REST auth v2 foundation checkpoint](reviews/phase-5s-rest-auth-v2-foundation-checkpoint.md)
- [Phase 5S WebSocket auth v3 verifier/admission checkpoint](reviews/phase-5s-ws-auth-v3-verifier-admission-checkpoint.md)
- [Phase 5S live transport cutover checkpoint](reviews/phase-5s-live-transport-cutover-2026-08-04.md)
- [Phase 5S REST auth v2 HTTP boundary checkpoint](reviews/phase-5s-rest-auth-v2-http-boundary-checkpoint.md)
- [Phase 5S 2026-07-20 end-of-day report](reviews/phase-5s-2026-07-20-end-of-day-report.md)

Эти документы являются внутренними инженерными review и evidence, а не
заключением независимого внешнего аудитора.

## Источники статуса

[INTEGRATION_ROADMAP.md](../INTEGRATION_ROADMAP.md) содержит текущие phase
gates и остающиеся release evidence. [VEIL_DESIGN.md](../VEIL_DESIGN.md)
содержит более широкий дизайн-контекст; наличие идеи там не означает, что она
реализована. [ROADMAP.md](../ROADMAP.md) следует читать вместе с актуальными
completion gates и кодом.

При конфликте утверждений проверяйте в таком порядке:

1. код, миграции и автоматические тесты текущего commit;
2. соответствующий completion gate или ADR;
3. INTEGRATION_ROADMAP;
4. обзорные и исторические документы.

## Правила документации

- отделяйте implemented, experimental, planned и unsupported;
- указывайте точный commit или версию для release/operations evidence;
- не называйте внутреннее review внешним аудитом;
- используйте синтетические данные и никогда не публикуйте секреты;
- обновляйте документацию в том же PR, где меняется observable contract;
- относительные ссылки должны работать из GitHub checkout.

Оригинальные материалы документации распространяются по
[AGPL-3.0-or-later](../LICENSE); сторонние материалы сохраняют собственные
notices.
