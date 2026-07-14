# Участие в разработке Veil

Спасибо за интерес к Veil. Issues и Pull Requests принимаются на русском или
английском языке.

Veil находится в pre-release разработке, не имеет стабильного API или формата
данных и ещё не проходил независимый криптографический аудит. Не описывайте
Preview как production-ready или externally audited.

## Перед началом

- Для обычной ошибки используйте Bug Report.
- Для изменения продукта или протокола используйте Feature Request.
- Вопросы установки и эксплуатации сначала сверяйте с [SUPPORT.md](SUPPORT.md).
- Уязвимости сообщайте **только приватно** по
  [SECURITY.md](SECURITY.md), не через публичный Issue или PR.
- Для крупного изменения сначала откройте Feature Request: это уменьшит риск
  реализовать несовместимый дизайн.

## Принципы изменений

Делайте PR небольшим и однородным. Не смешивайте исправление с массовым
реформатированием, обновлением зависимостей или несвязанным рефакторингом.
Сохраняйте существующие lock-файлы и обновляйте зависимости отдельным,
объяснимым изменением.

Для security-sensitive кода действуют обязательные границы:

- приватные ключи, E2EE state и долговременное расшифрованное хранилище
  остаются в native Rust boundary;
- при отсутствии ключей, roster proof или сессии отправка должна завершаться
  fail closed, без plaintext или ослабленного fallback;
- canonical server origin является частью identity; нельзя добавлять wildcard
  origins, HTTP downgrade или автоматическое доверие сертификату;
- plaintext сообщений, ключи, токены и recovery material нельзя писать в
  логи, fixtures, скриншоты или Issue;
- локальный поиск не должен создавать постоянный plaintext index;
- изменения Protobuf, криптографии, ACL, миграций, release/deploy chain и
  privacy surface требуют явного compatibility и security review.

Архитектурный обзор находится в [docs/architecture.md](docs/architecture.md),
а принятые решения и completion gates — в [docs/README.md](docs/README.md).

## Локальная проверка

Установите Rust/Cargo, Go, Node.js, pnpm и platform prerequisites для нужной
цели. PostgreSQL integration tests требуют работающий Docker.

Минимальный общий набор:

~~~powershell
git diff --check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets

Push-Location veil-server
go test ./...
go vet ./...
Pop-Location

Push-Location veil-desktop
pnpm install --frozen-lockfile
pnpm test:run
pnpm build
Pop-Location
~~~

Для изменений desktop UI также запустите **pnpm test:visual**. Для
server/database изменений выполните соответствующие integration tests:

~~~powershell
Push-Location veil-server
go test -count=1 -tags=integration -timeout 15m ./internal/integration/...
Pop-Location
~~~

Для mobile-изменений из каталога veil-mobile выполните **pnpm lint** и
**pnpm test -- --runInBand**. Документный PR может ограничиться релевантными
проверками, но в описании нужно честно перечислить, что именно не запускалось.

## Pull Request

В PR укажите:

- проблему и выбранное решение;
- затронутые компоненты и намеренно исключённый scope;
- влияние на privacy, crypto, protocol, storage, migrations и compatibility;
- выполненные проверки и их результат;
- migration/rollback notes для изменений данных или deployment;
- скриншоты для UI без реальных пользовательских данных;
- связанный Issue и обновлённую документацию, если контракт изменился.

Не добавляйте build artifacts, секреты, локальный .env или несаницированные
логи. Generated-файлы обновляйте воспроизводимой командой и указывайте её в PR.

## Лицензирование вклада

Veil распространяется по
[GNU AGPL v3.0 or later](LICENSE) (**AGPL-3.0-or-later**), правообладатель
оригинальных материалов — NaveLIL. Отправляя намеренный вклад для включения в
проект, вы подтверждаете, что имеете право его предоставить на тех же
условиях. Не копируйте код, данные или визуальные материалы с несовместимой
лицензией. Сторонний код должен сохранять авторство и лицензионные notices.

Товарные знаки регулируются отдельно в
[TRADEMARKS.md](TRADEMARKS.md).

## Общение

Соблюдайте [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Критикуйте техническое
решение, а не человека; явно отделяйте проверенный факт от предположения.
Maintainer может закрыть изменение, если оно небезопасно, не воспроизводится,
выходит за scope проекта или не имеет достаточных evidence/tests.
