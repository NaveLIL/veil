# Veil

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
docker compose up -d
```

Переменные для фаз 3 и 4. Без них соответствующие подсистемы стартуют в disabled-режиме — эндпоинты живые, трафик не пропускается:

```bash
export VEIL_UPLOAD_TOKEN_KEY="$(openssl rand -base64 32)"
export VEIL_PUSH_TRANSPORT_KEY="$(openssl rand -base64 32)"
export VEIL_PUSH_HASH_SALT="уникальное для деплоя значение"
```

## Крипто

XChaCha20-Poly1305 везде. X3DH для установки сессии, Double Ratchet для forward secrecy. Sender Keys для больших групп (>500 участников). Файлы — chunked AEAD, каждый чанк привязан к индексу и флагу final в nonce и AAD, детектирует перестановку/обрезание/замену. Push preview шифруется отдельным `K_push` — HKDF из ratchet root с domain separator. Взлом push = видны превью, не сами сообщения. SQLCipher, `cipher_memory_security = ON`. Seed в OS Keychain. На Linux: `keyring` v3 обязательно с фичами `sync-secret-service` + `crypto-rust`, иначе будет in-memory mock и всё потеряется при перезапуске. Сервер видит только ciphertext + метаданные (размер, тайминг).

## Где что сделано

Готово: identity/X3DH/ratchet, gateway + signed REST, resumable зашифрованные загрузки через tus.io, UnifiedPush/ntfy push-уведомления, группы/sender-keys/серверы-каналы-роли, локальный поиск с Cmd-K палитрой, базовая UI-библиотека (toast, sheet, switch, z-index слои).

Следующее: звонки (WebRTC), MLS-миграция для DM и маленьких групп, мобильный UI. См. [INTEGRATION_ROADMAP.md](INTEGRATION_ROADMAP.md).

## License

MIT
