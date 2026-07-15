# Краткая архитектура Veil

Veil — native-first E2EE messenger и self-hosted Veil Node. Текущая система
находится в pre-release разработке: отдельные completion gates закрыты, но
стабильный релиз и независимый security-аудит ещё отсутствуют.

## Контекст

~~~mermaid
flowchart LR
    subgraph Device["Пользовательское устройство"]
        UI["Desktop: SolidJS / Tauri"]
        Mobile["Mobile foundation: React Native"]
        FFI["Tauri commands / UniFFI"]
        Core["Rust protocol + crypto core"]
        Store["SQLCipher + OS key storage"]
        Search["Tantivy index in process memory"]

        UI --> FFI
        Mobile -. "foundation" .-> FFI
        FFI --> Core
        Core --> Store
        Core --> Search
    end

    Core <-->|"TLS/WSS, Protobuf, signed requests"| Node["Go Veil Node gateway"]
    Node --> DB["PostgreSQL: accounts, routing state, ciphertext"]
    Node --> Uploads["Upload volume: encrypted chunks"]
    Node --> Push["ntfy / push: generic wake-up"]
    Browser["Static site, Veil Link; Secure Share planned"] --> Node
~~~

Veil не имеет полноценного browser client. Web surfaces ограничены сайтом,
origin-hosted invitation preview и будущим узким Secure Share Viewer; они не
получают native account session или долговременные E2EE-ключи desktop-клиента.
Текущий share viewer является prototype и не подключён к production gateway.

## Компоненты репозитория

| Компонент | Ответственность |
|---|---|
| **veil-crypto** | Identity keys, X3DH, Double Ratchet, Sender Keys, AEAD и recovery primitives |
| **veil-store** | Origin-scoped SQLCipher state и интеграция с системным key storage |
| **veil-client** | WebSocket/Protobuf session, queue и crypto orchestration |
| **veil-search** | Локальный process-memory Tantivy index |
| **veil-uploads** | Resumable encrypted upload/download primitives |
| **veil-ffi** | UniFFI boundary для native mobile integration |
| **veil-mls** | Экспериментальный OpenMLS foundation, не включённый в текущий desktop runtime |
| **veil-desktop** | SolidJS UI и Tauri/Rust application boundary |
| **veil-mobile** | React Native/Expo foundation; production messaging runtime ещё не завершён |
| **veil-server** | Go gateway, auth, messaging, Spaces/ACL, push, uploads и Veil Link |
| **veil-proto** | Versioned wire contracts |
| **veil-share-viewer** | Экспериментальный WASM viewer prototype; production Secure Share не подключён |

Публичный production entry point Node — единый gateway. PostgreSQL migrations
выполняются отдельным one-shot этапом до запуска gateway; ошибка migration
должна блокировать partial deployment.

## Trust boundaries

### Устройство

Приватные ключи, ratchet/Sender-Key state и расшифрованное долговременное
хранилище принадлежат native Rust boundary. Recovery phrase может появляться в
WebView только в ограниченном onboarding/re-auth flow. JS UI не должен
становиться универсальным API чтения ключевого материала.

Отправка E2EE сообщения работает fail closed: отсутствие необходимой сессии,
roster proof или key distribution не разрешает plaintext либо ослабленный
fallback.

### Veil Node

Node маршрутизирует сообщения и хранит ciphertext, но неизбежно видит
метаданные транспорта: IP-адреса, время, размеры, account/conversation
membership и delivery state. E2EE не скрывает эту информацию.

Canonical HTTPS origin входит в identity аккаунта. Одинаковый user ID на двух
Node не означает одну identity. Wildcard origin, HTTP downgrade и
автоматическое доверие self-signed сертификату нарушают эту границу.

### Локальные данные и поиск

Долговременные данные клиента находятся в SQLCipher. Поисковый индекс
перестраивается из exact-origin хранилища и существует только в памяти
процесса; lock, account switch и origin switch должны очищать его.

### Attachments и push

Файл шифруется chunked AEAD до загрузки. Сервер получает encrypted chunks, а
filename, MIME и ключ передаются внутри E2EE payload. Push содержит только
ограниченный generic wake-up без plaintext preview; полные physical/device
release matrices ещё входят в открытые Preview gates.

## Crypto и access model

- Direct использует X3DH и Double Ratchet.
- Circle и text Room используют authenticated Sender Keys v5.
- Space/Room access задаётся server-side ACL, но presentation metadata не
  участвует в crypto trust.
- Изменение roster/access требует корректной key rotation/distribution.
- Key transparency пока отсутствует; текущая модель service-mediated TOFU.
- MLS и calls не являются включёнными пользовательскими функциями Preview.

Точные решения следует сверять с
[ADR-0001](adr/0001-authenticated-sender-keys-v5-for-server-channels.md)
и [review gates](README.md#reviews-и-completion-gates).

## Build, release и deployment

Rust, Go и desktop jobs проверяются раздельно в GitHub Actions. Публичные
desktop artifacts должны происходить из одного versioned tag, пройти общий
quality gate и публиковаться вместе с checksums и точным corresponding source.
Сайт показывает только установленный release manifest.

Production deployment использует immutable container reference, PostgreSQL,
one-shot migrations, upload volume, optional push service и внешний TLS
reverse proxy. Конкретная схема и rollback gate описаны в
[deploy/README.md](../deploy/README.md).

## Текущие ограничения

- нет stable release и обещанной обратной совместимости;
- нет независимого криптографического/security-аудита;
- mobile production runtime, calls и MLS runtime не завершены;
- key transparency отсутствует;
- attachment, multi-device и platform signing matrices требуют дальнейшего
  release evidence;
- доступность публичного Preview не является SLA.
