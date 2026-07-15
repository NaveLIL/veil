# Veil

<img src="assets/brand/phase-shift-mark.svg" width="88" alt="Veil Phase Shift logo">

[Русский](README.md) · [English](README.en.md)

[![Rust CI](https://github.com/NaveLIL/veil/actions/workflows/rust.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/rust.yml)
[![Go CI](https://github.com/NaveLIL/veil/actions/workflows/go.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/go.yml)
[![Desktop UI CI](https://github.com/NaveLIL/veil/actions/workflows/desktop-ui.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/desktop-ui.yml)
[![Mobile CI](https://github.com/NaveLIL/veil/actions/workflows/mobile.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/mobile.yml)
[![Security Audit](https://github.com/NaveLIL/veil/actions/workflows/security.yml/badge.svg)](https://github.com/NaveLIL/veil/actions/workflows/security.yml)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-663399.svg)](LICENSE)

Veil — native-first система защищённых личных и совместных пространств. Один
origin-scoped account и одна понятная модель доверия используются в Home,
Direct, Circle и структурированных Space/Room. Проект публикует версионированные
Preview-сборки, но ещё не достиг стабильного релиза: это не завершённый,
независимо проаудированный или подписанный production-продукт.

[Сайт проекта](https://veil.erez.pro/) ·
[Скачать Preview](https://veil.erez.pro/#download) ·
[Документация](docs/README.md) ·
[Безопасность](SECURITY.md) ·
[Участие в разработке](CONTRIBUTING.md)

> **Security boundary.** Операции с приватными ключами, E2EE state и
> расшифрованное долговременное хранилище остаются в Rust. Recovery phrase
> появляется в WebView только во время явного onboarding либо повторного
> показа после PIN re-authentication и не возвращается generic IPC-командой.
> Если требуемая криптографическая сессия, roster proof или распределение
> Sender Key недоступны, отправка блокируется fail closed — без plaintext или
> «упрощённого» fallback.

## Продуктовая модель

| Термин | Что означает |
|---|---|
| **Home** | личный центр: поиск, друзья, запросы и Direct |
| **Direct** | защищённый разговор один на один на X3DH + Double Ratchet |
| **Circle** | небольшая приватная группа с одной беседой на Sender Keys v5 |
| **Space** | совместное пространство с участниками, ролями и Rooms |
| **Room** | отдельный функциональный и криптографический контекст внутри Space |
| **Veil Node** | self-hosted инфраструктура и exact canonical origin аккаунта |
| **Node Access Pass** | одноразовый доступ к созданию одного аккаунта на закрытом Node; повторные входы его не требуют |
| **Veil Link** | ограниченное versioned приглашение в Space; не identity proof и не credential аккаунта |

Будущий **Community** — это публикационная форма совместного пространства с
постами, комментариями, реакциями и опросами. Она пока не реализована и не
считается простым переименованием Circle или готового Space: ей понадобятся
отдельные product/schema/privacy/security review и явная политика истории.

Браузерного клиента Veil нет и не планируется. Web-поверхности ограничены
статическим сайтом/документацией/загрузками, origin-hosted страницами Node
Access Pass и preview Veil Link, а также узким one-time Share Viewer. Они не
получают account session, recovery flow, историю сообщений или ключи
native-клиента.

## Текущее состояние

Авторитетный статус и критерии фаз находятся в
[INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md), а не выводятся из наличия
отдельного API или экрана.

- Baseline identity, X3DH/Double Ratchet, authenticated Sender Keys v5,
  SQLCipher, signed REST/WS, группы, Space/Room ACL и desktop Identity Island
  реализованы и покрыты соответствующими completion gates.
- Phase 2 local search закрыт финальным product/security gate. Реализация
  использует только process-memory Tantivy index из exact-origin SQLCipher,
  bounded coverage, атомарную live/rebuild publication и повторную SQLCipher
  hydration перед точной Direct/Circle/Room навигацией.
- Phase 4E Veil Spaces implementation и automated gate выполнены; физическая
  desktop↔desktop Veil Link/multi-device матрица остаётся обязательным release
  evidence.
- Phase 3B desktop attachments имеет существенную реализацию, но product gate
  остаётся открытым до физической upload/download/tamper/resume/media matrix.
- Phase 4P transport core и desktop management существуют, но native mobile
  clients и distributor/device matrix ещё не закрыты.
- Android имеет foundation/prototype, а production messaging остаётся Phase
  5A/5B. MLS runtime и звонки пока не включены как пользовательские функции.

Публичный Windows Preview собирается только в CI и всегда сопровождается
`SHA256SUMS`. До появления доверенного Authenticode-сертификата он явно
помечается как неподписанный и может вызвать SmartScreen/Smart App Control;
локальный development bundle официальным релизом не является.

## Архитектура

| Модуль | Язык | Назначение |
|---|---|---|
| `veil-crypto` | Rust | X3DH, Double Ratchet, XChaCha20-Poly1305, Sender Keys, chunked AEAD, BIP39 |
| `veil-store` | Rust | SQLCipher, origin-scoped state и OS Keychain integration |
| `veil-client` | Rust | WebSocket/Protobuf, offline queue и crypto orchestration |
| `veil-search` | Rust | process-memory-only Tantivy index с hard coverage budget |
| `veil-uploads` | Rust | resumable tus client и streaming chunked AEAD |
| `veil-ffi` | Rust | UniFFI bindings; высокоуровневая mobile runtime boundary ещё развивается |
| `veil-proto` | Protobuf | wire contracts |
| `veil-server` | Go | gateway, auth, messages, Spaces/ACL, push, uploads и invitation portal |
| `veil-desktop` | Rust + SolidJS | Tauri v2 desktop client и Island UI |
| `veil-mobile` | TypeScript + native Rust | React Native/Expo foundation; production runtime ещё не готов |
| `veil-mls` | Rust | экспериментальный OpenMLS foundation, выключенный в desktop runtime |
| `veil-share-viewer` | Rust/WASM | изолированный viewer для one-time secure-share capability |

## Security model и известные границы

- DM используют X3DH + Double Ratchet. Группы и text Rooms используют
  authenticated Sender Keys v5; изменение roster/access требует ротации, а
  незавершённая раздача блокирует отправку.
- Локальный поиск не создаёт persistent plaintext index: Tantivy живёт только
  в памяти процесса, перестраивается из SQLCipher для exact authenticated
  origin и очищается при lock/account/origin transition.
- Файлы шифруются chunked AEAD до загрузки. Сервер хранит ciphertext; filename,
  MIME и ключ находятся в E2EE payload. Product/physical gate всё ещё открыт.
- Push несёт только фиксированный generic wake-up без sender/message/
  conversation metadata и plaintext preview.
- Профильные имя/avatar/roles являются presentation metadata и никогда не
  участвуют в crypto trust, ACL или Sender-Key rotation.
- Текущий TOFU service-mediated: key transparency ещё отсутствует. Статус
  `Verified on this device` появляется только после явного независимого
  сравнения fingerprint и не наследуется новым identity key.
- Veil Node неизбежно видит routing metadata: размеры, время, account/
  conversation membership и сетевые адреса. E2EE не скрывает эти данные.
- Один account locator включает canonical server origin, user ID и identity
  key. Одинаковые UUID на разных self-hosted Node не считаются одним аккаунтом.

Подробные решения: [VEIL_DESIGN.md](VEIL_DESIGN.md),
[ADR Sender Keys v5](docs/adr/0001-authenticated-sender-keys-v5-for-server-channels.md)
и [completion gates](docs/reviews/).

## Требования для разработки

- Rust/Cargo и platform prerequisites для Tauri v2;
- Go;
- Node.js + pnpm;
- Docker Compose для PostgreSQL, migrations, gateway и ntfy;
- системные зависимости конкретной desktop/mobile target OS.

Dependencies зафиксированы lock-файлами. Не обновляйте их попутно без
отдельного review.

## Локальный Veil Node

Создайте локальный `.env` и замените placeholder secrets:

```powershell
Copy-Item .env.example .env
openssl rand -hex 32
# Запишите результат в VEIL_DB_PASSWORD и проверьте exact VEIL_WS_ORIGINS.
docker compose up -d --build
docker compose ps
```

Gateway разработки публикуется только на `127.0.0.1:9080`, ntfy — на
`127.0.0.1:9081`; PostgreSQL остаётся внутри Compose network. Одноразовый
`migrate` применяет все SQL migrations до запуска gateway. Ошибка migration
блокирует partial deployment.

Uploads и push намеренно fail closed, пока не заданы их ключи:

```powershell
openssl rand -base64 32
# Запишите результат в VEIL_UPLOAD_TOKEN_KEY внутри локального .env.
Push-Location veil-server
go run ./cmd/vapid-keygen
Pop-Location
# Запишите VAPID private key и subject в защищённую deployment-конфигурацию,
# затем примените конфигурацию через docker compose up -d --build.
```

Не используйте wildcard origin, HTTP fallback или автоматическое доверие
self-signed сертификату. Публичный Node должен иметь один canonical HTTPS/TLS
origin; LAN использует split-horizon DNS с тем же hostname, port и certificate
identity.

Для Caddy profile:

```powershell
$env:VEIL_PUBLIC_HOST = 'veil.example.com'
$env:VEIL_TLS_EMAIL = 'admin@example.com'
docker compose --profile proxy up -d --build
```

На `erez-vps` этот profile не используется: публичные 80/443 уже принадлежат
системному Nginx. Точная production-схема, backup gate, TLS/SNI и smoke checks
описаны в [deploy/README.md](deploy/README.md).

## Публичные релизы

Старые Linux-ветки и вручную собранные `Veil_0.1.0_*` не являются источником
релиза. Linux и Windows собираются из одного tag на актуальном `master`; если
общий quality gate или любая обязательная platform build падает, новый релиз
не публикуется и сайт не предлагает устаревший файл.

Tag вида `vMAJOR.MINOR.PATCH` запускает GitHub release workflow. Он проверяет
совпадение версии, собирает поддерживаемые desktop targets, создаёт стабильные
имена файлов, `SHA256SUMS` и `latest.json`, а затем публикует GitHub Release.
Тот же проверенный набор обязательно атомарно устанавливается через VPS
secrets в `/srv/veil/releases/current`; только после этого draft GitHub Release
становится публичным. Лендинг читает `latest.json`, поэтому версия, размеры и
доступные платформы обновляются без изменения HTML.

Windows job всегда обязан создать и проверить `.exe` и `.msi`. При наличии
обоих Authenticode secrets CI подписывает приложение и установщики; без них он
выпускает явно помеченный `unsigned` Preview. Один отсутствующий secret,
неверный PFX или ошибка подписи останавливают релиз без тихого downgrade.
Переменная `VEIL_REQUIRE_WINDOWS_SIGNING=true` позволяет полностью запретить
unsigned Preview после приобретения доверенного сертификата. macOS и Android
остаются недоступными до platform signing/notarization и отдельного gate.

## Desktop development и локальный Windows bundle

На Windows путь Rust target обязан быть ASCII. Кириллица в обычном workspace
target ломает upstream OpenSSL/nmake:

```powershell
$env:CARGO_TARGET_DIR = 'D:\veil-dev-target'
cargo build --workspace

Push-Location veil-desktop
pnpm install --frozen-lockfile
pnpm tauri dev
Pop-Location
```

Release bundle собирается отдельно:

```powershell
cargo install cargo-about --version 0.9.1 --locked --features cli
$env:CARGO_TARGET_DIR = 'D:\veil-release-target'
Push-Location veil-desktop
pnpm install --frozen-lockfile
pnpm tauri build
Pop-Location
```

NSIS появляется в
`D:\veil-release-target\release\bundle\nsis\`. Локальный bundle без явно
настроенной Authenticode-подписи — development artifact, а не опубликованный
CI Preview.

## Проверки перед checkpoint

```powershell
git diff --check
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets

Push-Location veil-server
go test ./...
go vet ./...
go test -count=1 -tags=integration -timeout 15m ./internal/integration/...
Pop-Location

Push-Location veil-desktop
pnpm test:run
pnpm build
pnpm test:visual
Pop-Location
```

Integration tests требуют готового Docker environment. Полный gate также
включает migrations, native smoke и platform-specific checks в объёме риска
изменения.

## Документация и участие

- [Документация](docs/README.md) и [текущая архитектура](docs/architecture.md)
- [Как внести вклад](CONTRIBUTING.md) и [правила сообщества](CODE_OF_CONDUCT.md)
- [Политика безопасности](SECURITY.md) и [каналы поддержки](SUPPORT.md)
- [История лицензирования (EN)](LICENSING.md), [уведомление](NOTICE) и
  [политика товарных знаков](TRADEMARKS.md)

## License

Copyright © 2026 NaveLIL.

Исходный код, документация и остальные оригинальные материалы Veil
распространяются по лицензии
[GNU Affero General Public License v3.0 or later](LICENSE)
(`AGPL-3.0-or-later`). При изменении сетевой версии Veil предоставьте её
пользователям доступ к соответствующему исходному коду на условиях лицензии.

Названия **Veil** и логотип **Phase Shift** не предоставляются как товарные
знаки и не должны использоваться так, будто сторонний форк является официальным.
Подробности — в [TRADEMARKS.md](TRADEMARKS.md). Сторонние зависимости сохраняют
собственные лицензии; воспроизводимый реестр и тексты уведомлений описаны в
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
