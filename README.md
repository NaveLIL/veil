# Veil

Veil — native-first система защищённых личных и совместных пространств. Один
origin-scoped account и одна понятная модель доверия используются в Home,
Direct, Circle и структурированных Space/Room. Проект ещё не выпускался и
сейчас находится в pre-release разработке: это не завершённый, независимо
проаудированный или подписанный production-релиз.

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
| **Veil Link** | ограниченное versioned приглашение в Space; не identity proof и не credential аккаунта |

Будущий **Community** — это публикационная форма совместного пространства с
постами, комментариями, реакциями и опросами. Она пока не реализована и не
считается простым переименованием Circle или готового Space: ей понадобятся
отдельные product/schema/privacy/security review и явная политика истории.

Браузерного клиента Veil нет и не планируется. Web-поверхности ограничены
статическим сайтом/документацией/загрузками, origin-hosted preview Veil Link и
узким one-time Share Viewer. Они не получают account session, recovery flow,
историю сообщений или ключи native-клиента.

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

Текущий Windows installer не подписан. Не распространяйте development bundle
как официальный релиз.

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

## Desktop development и Windows release

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
$env:CARGO_TARGET_DIR = 'D:\veil-release-target'
Push-Location veil-desktop
pnpm install --frozen-lockfile
pnpm tauri build
Pop-Location
```

NSIS появляется в
`D:\veil-release-target\release\bundle\nsis\`. До Phase 8 это unsigned
development artifact, а не публичный установщик.

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

## License

MIT
