# Veil

> Security boundary: private-key operations and decrypted storage stay in
> Rust. The recovery mnemonic is present in the WebView only during explicit
> onboarding or a PIN-reauthenticated recovery reveal; it is never returned by
> a generic IPC command. Network message paths fail closed when E2EE setup is
> unavailable.

E2EE мессенджер. Вся крипто — в Rust, UI просто рендерит то что приходит с Rust-стороны. Ключи не пересекают FFI-границу.

Переписал с нуля после того, как EREZ Secret вырос до 22k LOC монолита с криптой на TweetNaCl в JS. Подробнее в [VEIL_DESIGN.md](VEIL_DESIGN.md).

## Структура

| Модуль | Язык | Что делает |
|--------|------|------------|
| `veil-crypto` | Rust | X3DH, Double Ratchet, XChaCha20-Poly1305, chunked AEAD, BIP39 |
| `veil-store` | Rust | SQLCipher + OS Keychain |
| `veil-client` | Rust | WebSocket, Protobuf, offline queue, хук для FTS |
| `veil-search` | Rust | Локальный Tantivy индекс, данные никуда не уходят |
| `veil-uploads` | Rust | tus.io клиент + streaming chunked-AEAD |
| `veil-ffi` | Rust | UniFFI bindgen для Kotlin/Swift |
| `veil-proto` | Protobuf | Протокол |
| `veil-server` | Go | Gateway, auth, чат, группы, push, загрузки |
| `veil-desktop` | Rust + SolidJS | Tauri v2, Island UI, Cmd-K поиск |
| `veil-mobile` | TypeScript | React Native (Expo) |
| `veil-share-viewer` | Rust (WASM) | Расшифровка secure-share ссылок в браузере |

Go-пакеты в `veil-server/internal/`: `auth`, `authmw`, `chat`, `servers`, `gateway`, `push`, `uploads`, `metrics`, `integration`.

## Сборка

```bash
cargo build --workspace
cargo test  --workspace

cd veil-server && go build ./cmd/gateway/ && go test ./...

cd veil-desktop && pnpm install && pnpm tauri dev
cd veil-mobile  && pnpm install && npx expo start
```

## Запуск локально

```bash
cp .env.example .env
# Replace VEIL_DB_PASSWORD in .env with: openssl rand -hex 32
docker compose up -d
```

PostgreSQL is reachable only from the internal Compose network. The `migrate`
service applies every ordered SQL migration before the gateway starts; a
migration failure prevents an unsafe partial deployment.

Переменные для фаз 3 и 4. Без них соответствующие подсистемы стартуют в disabled-режиме — эндпоинты живые, трафик не пропускается:

```bash
export VEIL_UPLOAD_TOKEN_KEY="$(openssl rand -base64 32)"
export VEIL_PUSH_TRANSPORT_KEY="$(openssl rand -base64 32)"
export VEIL_PUSH_HASH_SALT="уникальное для деплоя значение"
```

## Публичный деплой с TLS

Caddy перед gateway: автоматически тянет Let's Encrypt сертификат, проксирует и лендинг, и WebSocket, и REST через один домен. Конфиг в [Caddyfile](Caddyfile).

```bash
export VEIL_PUBLIC_HOST=secret.erez.pro
export VEIL_TLS_EMAIL=admin@example.com
docker compose --profile proxy up -d
```

Клиенты после этого подключаются по `wss://secret.erez.pro/ws`, REST — `https://secret.erez.pro/v1/*`. На корне домена — лендинг, встроенный в gateway бинарник.

## Крипто

XChaCha20-Poly1305 используется для содержимого. X3DH устанавливает сессию, Double Ratchet даёт forward secrecy в DM; ratchet-header аутентифицирован, но не скрыт от сервера. Группы и каналы используют Sender Keys v5: каждое сообщение дополнительно подписано Ed25519 владельцем ключа, состав привязан к обязательной ротации, а незавершённая раздача блокирует отправку. MLS остаётся отдельным экспериментальным crate и не включён в desktop runtime. Файлы — chunked AEAD с привязкой индекса/final и атомарной публикацией только после полной проверки; текущий one-shot adapter ограничен 64 MiB. Push-транспорт существует, но содержимое push-preview в desktop пока отключено до полного `K_push` workflow. SQLCipher работает с `cipher_memory_security = ON` и `synchronous = FULL`, seed хранится в OS Keychain. Копирование recovery phrase из UI отключено из-за Windows Clipboard History/cloud sync. На Linux `keyring` v3 собирается с `sync-secret-service` + `crypto-rust`. Сервер видит ciphertext и неизбежные метаданные (размер, тайминг, участники/маршрутизация).

## Где что сделано

Готово: identity/X3DH/ratchet, gateway + signed REST, resumable зашифрованные загрузки через tus.io, UnifiedPush/ntfy push-уведомления, группы/sender-keys/серверы-каналы-роли, локальный поиск с Cmd-K палитрой, базовая UI-библиотека (toast, sheet, switch, z-index слои).

Следующее: звонки (WebRTC), MLS-миграция для DM и маленьких групп, мобильный UI. См. [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md).

## License

MIT
