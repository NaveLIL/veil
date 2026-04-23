# VEIL — заметки по архитектуре

> Рабочее название: **Veil**
> Альтернативы которые рассматривал: Bastion, Aegis, Citadel, Phantom — остановился на Veil

---

## 0. Почему не рефакторить EREZ Secret

| Проблема EREZ | Масштаб | Почему не чинится |
|---|---|---|
| server.js = 22,600 LOC монолит | Критический | Любое изменение ломает 10 мест. 75+ хендлеров в одном файле |
| app.js = 8,440 LOC без фреймворка | Критический | Vanilla DOM manipulation, нет компонентов, нет state management |
| Крипто на TweetNaCl (JS) | Высокий | На мобильных тормозит PBKDF2 (600K итераций в JS), Double Ratchet lag |
| Web-клиент как основной | Высокий | XSS, расширения, devtools dump, WASM overhead — всё это attack surface |
| 68 WS типов без версионирования | Высокий | Нельзя обновить протокол без поломки всех клиентов |
| SQLite + PG dual driver | Средний | 350+ LOC абстракции, баги при переключении |
| Нет API документации | Высокий | Только WS, нет REST, нет OpenAPI, нет gRPC |
| Multi-device архитектура | Высокий | In-memory state, теряется при рестарте |

**Вывод**: Проще построить правильно с нуля, забрав проверенные идеи.

---

## 1. Архитектурная Философия: Native-Only

### Почему отказываемся от Web-клиента

| Проблема Web-клиента | Как решает Native |
|---|---|
| **XSS** — инъекция скриптов крадёт ключи из JS heap | Ключи живут в Rust памяти, JS к ним не обращается |
| **Расширения браузера** — могут читать DOM, LocalStorage | Нет расширений, нет DOM с секретами |
| **DevTools** — любой может сделать memory dump | Процесс защищён ОС, mlock() для страниц с ключами |
| **WASM overhead** — 3-5x медленнее native Rust | Прямой FFI, нулевой overhead |
| **LocalStorage** — единственное хранилище, нет encryption at rest | OS Keychain (macOS Keychain, Android Keystore, Linux Secret Service) |
| **CDN/MITM** — серверу доверяем при загрузке JS | Бинарник подписан, certificate pinning, reproducible builds |
| **Service Worker** — ненадёжный offline | SQLite на клиенте, полный offline |
| **Нет push** — только pull через WS | Нативный FCM/APNs, фоновый сервис |

### Принципы

1. **Native-only клиенты**: Desktop (Tauri v2) + Mobile (React Native). Никакого web-клиента
2. **Крипто = Rust, везде**: один crate, прямой FFI (не WASM), ключи никогда не покидают Rust boundary
3. **Zero JS crypto**: TypeScript/React только для UI рендеринга, вся криптография — Rust native
4. **OS Keychain**: seed/ключи хранятся в защищённом хранилище ОС, не в файлах
5. **Certificate pinning**: клиент проверяет TLS сертификат сервера, MITM невозможен
6. **Memory protection**: mlock() для страниц с ключами, zeroize on drop
7. **Sealed sender**: сервер не знает, кто отправил сообщение (метаданные минимальны)
8. **Protocol-first**: Protobuf контракт, затем реализация
9. **Offline-first**: клиент работает без сети, локальная SQLite БД
10. **Единственное исключение для Web**: Share Viewer — легковесная страница для просмотра secure links

---

## 2. Высокоуровневая Архитектура

```
┌──────────────────────────────────────────────────────────────────┐
│                     НАТИВНЫЕ КЛИЕНТЫ                             │
│                                                                  │
│  ┌────────────────────┐          ┌─────────────────────────┐     │
│  │ Desktop (Tauri v2) │          │ Mobile (React Native)   │     │
│  │                    │          │                         │     │
│  │  ┌──────────────┐  │          │  ┌───────────────────┐  │     │
│  │  │  UI Layer    │  │          │  │  UI Layer         │  │     │
│  │  │  React/Solid │  │          │  │  RN Components    │  │     │
│  │  └──────┬───────┘  │          │  └────────┬──────────┘  │     │
│  │         │ IPC      │          │           │ JSI (sync)  │     │
│  │  ┌──────┴───────┐  │          │  ┌────────┴──────────┐  │     │
│  │  │ Rust Core    │  │          │  │ Rust Core (JNI/   │  │     │
│  │  │ veil-crypto  │  │          │  │ Swift FFI)        │  │     │
│  │  │ veil-client  │  │          │  │ veil-crypto       │  │     │
│  │  │ veil-store   │  │          │  │ veil-client       │  │     │
│  │  └──────┬───────┘  │          │  │ veil-store        │  │     │
│  │         │          │          │  └────────┬──────────┘  │     │
│  │  ┌──────┴───────┐  │          │  ┌────────┴──────────┐  │     │
│  │  │ OS Keychain  │  │          │  │ Android Keystore  │  │     │
│  │  │ Stronghold   │  │          │  │ iOS Keychain      │  │     │
│  │  └──────────────┘  │          │  └───────────────────┘  │     │
│  │  ┌──────────────┐  │          │  ┌───────────────────┐  │     │
│  │  │ Local SQLite │  │          │  │ Local SQLite      │  │     │
│  │  │ (encrypted)  │  │          │  │ (encrypted)       │  │     │
│  │  └──────────────┘  │          │  └───────────────────┘  │     │
│  └─────────┬──────────┘          └───────────┬─────────────┘     │
│            │                                 │                    │
│            └──────────┬──────────────────────┘                    │
│                       │ TLS 1.3 + Certificate Pinning             │
│                       │ Protobuf over WebSocket                   │
└───────────────────────┼──────────────────────────────────────────┘
                        │
  ┌─────────────────────┴──────────────────────────────────────┐
  │                   СЕРВЕРНАЯ ЧАСТЬ (Go)                       │
  │                                                             │
  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
  │  │  Gateway     │  │  REST API    │  │  Share Viewer    │  │
  │  │  (WebSocket) │  │  (OpenAPI)   │  │  (static HTML)   │  │
  │  └──────┬───────┘  └──────┬───────┘  └──────────────────┘  │
  │         │                 │                                  │
  │  ┌──────┴─────────────────┴──────────────────────────────┐  │
  │  │                 NATS JetStream                        │  │
  │  └──┬───────┬──────────┬──────────┬──────────┬───────────┘  │
  │     │       │          │          │          │               │
  │  ┌──┴──┐ ┌──┴───┐ ┌───┴──┐ ┌────┴───┐ ┌───┴────────┐     │
  │  │Chat │ │Media │ │Auth  │ │Share   │ │Presence    │     │
  │  │ Svc │ │ Svc  │ │ Svc  │ │ Svc    │ │ Svc        │     │
  │  └──┬──┘ └──┬───┘ └──┬───┘ └───┬────┘ └────────────┘     │
  │     │       │        │         │                           │
  │  ┌──┴───────┴────────┴─────────┴───────────────────────┐  │
  │  │  PostgreSQL   │  Redis   │  S3/MinIO   │  NATS      │  │
  │  └─────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────┘
```

---

## 3. Стек Технологий

### 3.1 Rust Core: Три Crate'а

Вся клиентская логика (крипто, протокол, хранилище) живёт в Rust. UI-слой лишь вызывает Rust-функции через FFI. **Ключи никогда не покидают Rust memory boundary.**

#### `veil-crypto` — Криптографический движок

| Компонент | Библиотека | Назначение |
|---|---|---|
| X25519 ECDH | `x25519-dalek` | Обмен ключами |
| Ed25519 | `ed25519-dalek` | Подписи, аутентификация |
| XChaCha20-Poly1305 | `chacha20poly1305` | Шифрование сообщений |
| HKDF-SHA256 | `hkdf` | Деривация ключей |
| Argon2id | `argon2` | KDF для PIN/пароля |
| Double Ratchet | Собственная реализация | Forward secrecy для DM |
| X3DH | Собственная реализация | Установка сессии |
| BIP39 | `bip39` | Мнемоника (12 слов) |
| Random | `rand` + `getrandom` | CSPRNG |
| Zeroize | `zeroize` | **Стирание ключей из памяти при drop** |

**Защита памяти (native-only преимущество):**
```rust
use zeroize::Zeroize;
use memsec::mlock;  // Запрет swap для страниц с ключами

#[derive(Zeroize)]
#[zeroize(drop)]    // При drop — память зануляется
struct SessionKeys {
    root_key: [u8; 32],
    chain_key: [u8; 32],
    // ...
}

// mlock() — ОС не сбросит эти страницы в swap
unsafe { mlock(keys_ptr, keys_size); }
```

> В WASM/JS это **невозможно** — GC может копировать ключи в памяти, нет mlock, нет гарантии зануления.

#### `veil-client` — Протокольный движок

Полностью на Rust. Управляет WebSocket-соединением, Protobuf сериализацией, очередью отправки, offline-буфером. UI-слой не знает о протоколе.

```rust
// Пример API для UI-слоя
pub struct VeilClient { /* ... */ }

impl VeilClient {
    pub fn connect(&mut self, server_url: &str) -> Result<()>;
    pub fn send_message(&self, conv_id: &str, plaintext: &[u8]) -> Result<MessageId>;
    pub fn get_conversations(&self) -> Vec<Conversation>;
    pub fn get_messages(&self, conv_id: &str, limit: u32) -> Vec<DecryptedMessage>;
    pub fn create_share(&self, payload: &[u8], password: Option<&str>, ttl_secs: u64) -> Result<ShareUrl>;
    // ... всё шифрование происходит внутри, UI получает plaintext
}
```

#### `veil-store` — Локальное хранилище

- **SQLCipher** (зашифрованная SQLite) для сообщений, контактов, состояния ratchet
- **OS Keychain** ( macOS Keychain / Android Keystore / Linux Secret Service) для seed
- Полный offline: клиент работает без сети, синхронизация при reconnect

```
Rust Core (shared across all platforms):
├── veil-crypto/        # Криптография, zero-copy, zeroize-on-drop
│   ├── src/
│   │   ├── lib.rs
│   │   ├── keys.rs         # BIP39, Argon2id key derivation
│   │   ├── ratchet.rs      # Double Ratchet (Signal protocol)
│   │   ├── x3dh.rs         # Extended Triple Diffie-Hellman
│   │   ├── aead.rs         # XChaCha20-Poly1305 + 256-byte padding
│   │   ├── kdf.rs          # HKDF-SHA256, Argon2id
│   │   ├── signature.rs    # Ed25519
│   │   ├── share.rs        # Secure share encrypt/decrypt
│   │   └── sealed.rs       # Sealed sender (скрытие отправителя)
│   └── tests/
│       └── vectors.rs      # RFC test vectors
│
├── veil-client/        # Протокольный движок
│   ├── src/
│   │   ├── lib.rs
│   │   ├── connection.rs   # WebSocket + TLS + cert pinning
│   │   ├── protocol.rs     # Protobuf encode/decode
│   │   ├── sync.rs         # Offline queue, message ordering
│   │   ├── sessions.rs     # Ratchet session management
│   │   └── api.rs          # Public API for UI layer
│   └── tests/
│
├── veil-store/         # Локальное зашифрованное хранилище
│   ├── src/
│   │   ├── lib.rs
│   │   ├── db.rs           # SQLCipher wrapper
│   │   ├── keychain.rs     # OS keychain (keyring crate)
│   │   ├── models.rs       # Conversations, Messages, Contacts
│   │   └── migrations.rs   # Schema versioning
│   └── tests/
│
└── veil-ffi/           # FFI bindings generator
    ├── src/lib.rs
    ├── uniffi.toml         # Mozilla UniFFI config
    └── veil.udl            # UniFFI Definition Language
```

#### Генерация FFI биндингов: Mozilla UniFFI

Вместо ручного написания JNI/Swift bindings используем **UniFFI** (Mozilla, используется в Firefox):

```
veil.udl → uniffi-bindgen → Kotlin bindings (Android)
                          → Swift bindings (iOS)
                          → TypeScript bindings (Tauri IPC)
```

Один `.udl` файл, автоматическая генерация для всех платформ. Типобезопасно.

### 3.2 Desktop: Tauri v2

**Tauri v2** = WebView для UI + нативный Rust для всего остального.

**Критическое отличие от EREZ Tauri**: в EREZ крипто было в JS внутри WebView. В Veil крипто — в Tauri commands (Rust), WebView только рендерит UI.

```
desktop/
├── src-tauri/
│   ├── Cargo.toml          # Depends on veil-crypto, veil-client, veil-store
│   ├── src/
│   │   ├── main.rs         # Window lifecycle
│   │   ├── commands.rs     # Tauri IPC commands (thin wrappers over veil-client)
│   │   ├── tray.rs         # System tray
│   │   ├── pinning.rs      # TLS certificate pinning
│   │   └── updater.rs      # Auto-update (Ed25519-signed)
│   └── tauri.conf.json
│
├── src/                     # UI (runs inside WebView)
│   ├── App.tsx              # React / Solid.js
│   ├── components/          # Chat UI, lists, modals
│   ├── stores/              # Zustand/Solid stores (UI state only!)
│   ├── hooks/               # useTauriCommand() wrappers
│   └── i18n/                # EN/RU
├── package.json
└── vite.config.ts
```

**Поток данных (Desktop):**
```
[User types message]
  → React state (plaintext)
    → invoke('send_message', { conv_id, text })  // Tauri IPC
      → Rust: veil-client.send_message()
        → veil-crypto: encrypt(ratchet_session, plaintext)
          → XChaCha20-Poly1305(message_key, padded_plaintext)
        → veil-client: encode Protobuf Envelope
        → WebSocket → Server
        → veil-store: save to SQLCipher
      → Return message_id to React
```

**Ключи никогда не проходят через IPC.** React не видит ключей, nonce, ciphertext. Только plaintext и метаданные.

**Функции Desktop:**
- Системный трей (свернуть, quick reply)
- Автозапуск (системный сервис)
- Нативные уведомления
- Deep links: `veil://add/{publicKey}`, `veil://share/{id}`
- Auto-update (Ed25519-подписанные бинарники)
- Stronghold (Tauri) для дополнительного шифрования seed в keychain
- Builds: `.deb`, `.AppImage`, `.dmg`, `.msi`

### 3.3 Mobile: React Native + Rust JSI

**React Native** для UI + **Rust через JSI** (JavaScript Interface) для крипто.

JSI = синхронные вызовы C++/Rust из JS **без bridge overhead**. В отличие от старого RN bridge (async JSON serialization), JSI — это прямой вызов нативной функции.

```
mobile/
├── App.tsx
├── src/
│   ├── screens/
│   │   ├── AuthScreen.tsx       # BIP39 seed entry / PIN
│   │   ├── ConversationList.tsx # DM + Groups + Servers
│   │   ├── ChatScreen.tsx       # Message view
│   │   ├── ShareCreate.tsx      # Create secure share
│   │   └── Settings.tsx
│   ├── stores/                  # Zustand (UI state only)
│   ├── components/              # Message bubble, input, etc.
│   ├── i18n/                    # EN/RU
│   └── native/
│       └── VeilModule.ts        # TypeScript types for JSI bridge
│
├── native/                      # Rust → C → JNI/Swift
│   ├── Cargo.toml               # Depends on veil-crypto, veil-client, veil-store
│   ├── src/
│   │   ├── lib.rs               # JNI exports (Android)
│   │   └── ios.rs               # Swift exports (iOS)
│   ├── build-android.sh         # cargo ndk → .so
│   └── build-ios.sh             # cargo lipo → .a
│
├── android/
│   └── app/src/main/java/.../VeilNativeModule.java  # JNI bridge
├── ios/
│   └── VeilNativeBridge.swift   # Swift bridge
│
├── app.json
└── package.json
```

**Поток данных (Mobile):**
```
[User types message]
  → React Native state
    → VeilModule.sendMessage(convId, text)  // JSI — синхронный вызов!
      → JNI → Rust: veil-client.send_message()
        → veil-crypto: encrypt (native speed, не JS!)
        → WebSocket → Server
        → veil-store: save to SQLCipher
      → Return message_id
```

**Преимущества vs EREZ Mobile:**

| | EREZ Mobile | Veil Mobile |
|---|---|---|
| **Крипто** | JS (TweetNaCl в RN) | Rust native через JSI |
| **Key derivation** | 2-3 сек (PBKDF2 в JS) | ~200ms (Argon2id в Rust) |
| **Double Ratchet** | JS event loop (lag) | <0.5ms synchronous Rust |
| **Key storage** | AsyncStorage (plaintext!) | Android Keystore / iOS Keychain |
| **Offline** | Нет | SQLCipher с полным offline |
| **Push** | Нет | FCM + APNs (нативный) |
| **Background** | Нет (WebSocket умирает) | Foreground service (Android), Background App Refresh (iOS) |

### 3.4 Shared UI Assets

Desktop (Tauri) и Mobile (RN) имеют разные UI-фреймворки, но мы можем расшарить:

| Что | Как | Где |
|---|---|---|
| Протокол (protobuf types) | Автогенерация из `.proto` | `proto/` → TS types |
| i18n строки | Единые JSON файлы | `shared/i18n/` |
| Тема/цвета | CSS variables (desktop) / RN theme (mobile) | `shared/theme/` |
| Иконки | Lucide icons (оба поддерживают) | — |
| API types | TypeScript interfaces (генерация из UniFFI) | `shared/types/` |
| Бизнес-логика UI** | — | **НЕ шарим**, UI платформо-специфичный |

> **\*\*Принцип**: Не шарим UI-компоненты между desktop и mobile. Каждая платформа имеет native UX паттерны. Но шарим всю бизнес-логику (она в Rust).

### 3.5 Desktop UI: Адаптация Open-Source

Для UI внутри Tauri WebView берём готовый компонентный фреймворк:

| Вариант | Плюс | Минус |
|---|---|---|
| **Revolt frontend** (Solid.js) | Discord-style, серверы/каналы/DM, красивый | AGPL, Solid.js (не mainstream) |
| **Custom React** + `@radix-ui` | Полный контроль, MIT, огромная экосистема | Больше работы с нуля |
| **Svelte** + `shadcn-svelte` | Лёгкий, быстрый, отличный DX | Меньше готовых чат-компонентов |

**Рекомендация**: Revolt fork для десктопа (идеальный UI для нашего случая), но вся крипто/протокол логика вырезается и заменяется на Tauri IPC → Rust. Revolt UI становится "тупой" оболочкой.

### 3.6 Протокол: Protobuf + WebSocket

**Почему Protobuf**: типизация, версионирование, компактность (vs JSON в EREZ).

Protobuf кодируется/декодируется в Rust (`prost` crate), не в TypeScript. UI получает уже чистые данные.

```protobuf
// proto/veil/v1/envelope.proto
syntax = "proto3";
package veil.v1;

message Envelope {
  uint64 seq = 1;
  uint64 timestamp = 2;
  oneof payload {
    SendMessage send_message = 10;
    MessageAck message_ack = 11;
    TypingEvent typing = 12;
    PresenceUpdate presence = 13;
    AuthChallenge auth_challenge = 20;
    AuthResponse auth_response = 21;
    PreKeyBundle prekey_bundle = 22;
    SenderKeyDistribution sender_key_dist = 30;
    GroupEvent group_event = 31;
    ServerEvent server_event = 32;
    ShareCreate share_create = 40;
    ShareView share_view = 41;
    VoiceToken voice_token = 50;
    // ~25-30 типов (vs 68 в EREZ)
  }
}

message SendMessage {
  string conversation_id = 1;
  bytes ciphertext = 2;        // Зашифровано в Rust, непрозрачно для сервера
  bytes header = 3;            // Encrypted ratchet header
  MessageType type = 4;
  optional string reply_to = 5;
  optional uint32 ttl_seconds = 6;
  repeated EncryptedAttachment attachments = 7;
}

// Sealed Sender: сервер не знает кто отправил
message SealedEnvelope {
  bytes sender_certificate = 1;  // Зашифровано для получателя
  bytes ciphertext = 2;
}
```

### 3.7 Бэкенд: Go Микросервисы

**Почему Go**: goroutines для WebSocket (1M+ соединений), простой деплой, отличная stdlib.

**Сервер НЕ видит**: содержимое сообщений, ключи, имена файлов. Сервер — слепой маршрутизатор.

| Сервис | Ответственность |
|---|---|
| `veil-gateway` | WebSocket мультиплексор, auth, rate limit, cert management |
| `veil-chat` | Store-and-forward сообщений, delivery receipts |
| `veil-auth` | Challenge-response, prekey storage, device registry |
| `veil-media` | Encrypted blob upload/download, thumbnails (client-side encrypted) |
| `veil-share` | Secure links: TTL, view counter, auto-purge, password rate-limit |
| `veil-presence` | Online/offline, typing, last-seen |
| `veil-voice` | LiveKit token generation, room management |
| `veil-push` | FCM/APNs delivery |

```
server/
├── go.mod
├── cmd/
│   ├── gateway/main.go
│   ├── chat/main.go
│   ├── auth/main.go
│   ├── media/main.go
│   ├── share/main.go
│   ├── presence/main.go
│   ├── voice/main.go
│   ├── push/main.go
│   └── allinone/main.go     # Все сервисы в одном бинарнике (easy deploy)
├── internal/
│   ├── gateway/              # WebSocket handler, connection pool
│   ├── chat/                 # Message routing, fan-out
│   ├── auth/                 # Ed25519 challenge-response
│   ├── media/                # S3 proxy
│   ├── share/                # CRUD with TTL cleanup goroutine
│   ├── presence/             # Redis-backed presence
│   ├── models/               # DB models (sqlc generated)
│   ├── middleware/            # Auth, logging, metrics (Prometheus)
│   └── config/               # Env-based config
├── pkg/
│   └── protocol/             # Protobuf helpers
├── migrations/
│   └── *.sql
├── Makefile
└── Dockerfile
```

**Режим "всё в одном"**: `veil-allinone` запускает все сервисы + embedded NATS в одном процессе. Идеально для self-hosting.

### 3.8 Share Viewer: Единственная Web-страница

Secure Shares — ссылки, которые любой может открыть в браузере. Для этого нужен **минимальный** web-viewer.

```
share-viewer/
├── index.html          # Один файл, inline JS/CSS
├── veil-crypto.wasm    # ТОЛЬКО decrypt + Argon2id (минимальный WASM ~50KB)
└── (опционально: Go template, рендерится сервером)
```

Это **единственное место** где используется WASM. И это ок, т.к. share viewer:
- Не хранит ключи (ключ в URL fragment, одноразовый)
- Не имеет сессии (stateless)
- Минимальная attack surface (один файл, нет зависимостей)
- Пароль → Argon2id → decrypt → показать — и всё

---

## 4. Криптографический Протокол (Улучшенный)

### 4.1 Идентичность

```
Seed (BIP39 12 слов, 128-бит энтропия)
  ↓ Argon2id (64MB, 3 итерации, 4 параллелизма)
  ↓ 64 байта
  ├─ [0..31] → X25519 Identity Key (IK)
  └─ [32..63] → Ed25519 Signing Key (SK)
```

**Отличие от EREZ**: Argon2id вместо PBKDF2 — устойчив к GPU/ASIC атакам.

### 4.2 Установка Сессии: X3DH (улучшенный)

```
Alice → Сервер: Публикует IK_a, SPK_a (signed prekey), OPK_a[] (one-time prekeys)
Bob начинает сессию:
  1. Забирает IK_a, SPK_a, OPK_a[0] с сервера
  2. Генерирует ephemeral key EK_b
  3. Вычисляет:
     DH1 = X25519(IK_b, SPK_a)
     DH2 = X25519(EK_b, IK_a)
     DH3 = X25519(EK_b, SPK_a)
     DH4 = X25519(EK_b, OPK_a)  // если доступен
  4. SK = HKDF(DH1 || DH2 || DH3 || DH4)
  5. Инициализирует Double Ratchet с SK
```

### 4.3 Шифрование Сообщений: Double Ratchet

Аналогичен реализации в EREZ `core/ratchet.js`, но:
- **На Rust** — нет GC пауз, предсказуемое время выполнения
- **XChaCha20-Poly1305** вместо XSalsa20 — больше nonce (24 байта, безопасны как random)
- **Header encryption** — скрываем ratchet public key от сервера
- **Out-of-order tolerance** — буфер до 1000 пропущенных сообщений (vs потенциальные проблемы в EREZ)

### 4.4 Группы: Sender Keys (улучшенные)

```
                    ┌──────────────┐
                    │ Group Chain  │
                    │ Key (GCK)    │
                    └──────┬───────┘
                           │ HKDF
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         Message Key 1  MK 2        MK 3 ...
```

- Каждый участник имеет свой Sender Key
- При join/leave — Sender Key Rotation (новый ключ для каждого оставшегося)
- **Отличие от EREZ**: MLS (Messaging Layer Security) в будущем для групп >50 участников

### 4.5 Secure Shares (главная фишка!)

```
Создание:
  1. content_key = random 32 bytes
  2. ciphertext = XChaCha20-Poly1305(content_key, payload)
  3. Если пароль: wrapped_key = XChaCha20(Argon2id(password), content_key)
     Если без пароля: wrapped_key = content_key (в URL fragment)
  4. POST /share → {id, ciphertext, wrapped_key(?), ttl, max_views}
  5. URL: https://veil.app/s/{id}#{content_key_base64}  // fragment не уходит на сервер

Просмотр:
  1. GET /share/{id} → {ciphertext, wrapped_key?, views_left, expires_at}
  2. Если пароль: content_key = decrypt(Argon2id(password), wrapped_key)
  3. Decrypt payload client-side
  4. View counter++ server-side
  5. При max_views → automatic purge
```

**Улучшения vs EREZ:**
- Argon2id вместо PBKDF2 для пароля
- Серверная rate-limit на попытки ввода пароля (anti-brute-force)
- Поддержка файлов до 100MB (потоковое шифрование)
- QR-код для мобильного доступа

---

## 5. База Данных

### PostgreSQL (единственный вариант, без SQLite dual-mode)

```sql
-- Unified conversations model (DM, Group, Channel → одна таблица)
CREATE TABLE conversations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type        SMALLINT NOT NULL,  -- 0=DM, 1=GROUP, 2=CHANNEL
    server_id   UUID REFERENCES servers(id),
    name        TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Все сообщения в одной таблице (партиционирование по дате)
CREATE TABLE messages (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID NOT NULL REFERENCES conversations(id),
    sender_key      BYTEA NOT NULL,       -- 32 bytes public key
    ciphertext      BYTEA NOT NULL,
    nonce           BYTEA NOT NULL,       -- 24 bytes
    msg_type        SMALLINT DEFAULT 0,
    reply_to        UUID,
    expires_at      TIMESTAMPTZ,          -- Disappearing messages
    created_at      TIMESTAMPTZ DEFAULT now()
) PARTITION BY RANGE (created_at);

-- Партиции по месяцам (автоматическое управление)
CREATE TABLE messages_2026_04 PARTITION OF messages
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');

-- Users (минимум данных на сервере)
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identity_key    BYTEA UNIQUE NOT NULL, -- X25519 public key
    signing_key     BYTEA UNIQUE NOT NULL, -- Ed25519 public key
    username        TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Devices (multi-device)
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    device_key      BYTEA UNIQUE NOT NULL,
    device_name     TEXT,
    last_seen       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Prekeys for X3DH
CREATE TABLE prekeys (
    id              BIGSERIAL PRIMARY KEY,
    device_id       UUID NOT NULL REFERENCES devices(id),
    key_type        SMALLINT NOT NULL, -- 0=signed, 1=one-time
    public_key      BYTEA NOT NULL,
    signature       BYTEA,            -- only for signed prekeys
    used            BOOLEAN DEFAULT false
);

-- Servers (Discord-like)
CREATE TABLE servers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    icon_url    TEXT,
    owner_id    UUID NOT NULL REFERENCES users(id),
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Roles & Permissions (bitmask)
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id   UUID NOT NULL REFERENCES servers(id),
    name        TEXT NOT NULL,
    permissions BIGINT DEFAULT 0,
    position    SMALLINT DEFAULT 0
);

-- Secure Shares
CREATE TABLE shares (
    id              TEXT PRIMARY KEY,       -- short random ID
    ciphertext      BYTEA NOT NULL,
    has_password    BOOLEAN DEFAULT false,
    max_views       INTEGER DEFAULT 1,
    views           INTEGER DEFAULT 0,
    expires_at      TIMESTAMPTZ NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Sender Keys (group E2E)
CREATE TABLE sender_keys (
    conversation_id UUID NOT NULL,
    owner_device_id UUID NOT NULL,
    target_device_id UUID NOT NULL,
    encrypted_key   BYTEA NOT NULL,
    generation      INTEGER DEFAULT 0,
    PRIMARY KEY (conversation_id, owner_device_id, target_device_id)
);
```

---

## 6. Фичи: Что Берём из EREZ

### ✅ Забираем (проверено, работает)

| Фича | Приоритет | Примечание |
|---|---|---|
| E2E DM с Double Ratchet | P0 | Ядро продукта |
| E2E группы (Sender Keys) | P0 | Ядро продукта |
| Серверы + каналы + роли | P0 | Desktop: Revolt UI fork. Mobile: RN native |
| Secure Shares с паролем + TTL | P0 | **Уникальная фишка**. Web-viewer только для получателей |
| Disappearing Messages | P0 | TTL от 30с до 7 дней |
| BIP39 мнемоника | P0 | Восстановление аккаунта |
| PIN-lock | P1 | Быстрая разблокировка |
| View-Once фото | P1 | Конфиденциальные фото |
| Read Receipts (✓✓) | P1 | |
| Typing Indicators | P1 | |
| Emoji-fingerprint верификация | P1 | Signal-стиль |
| Message Replies + Edit + Delete | P1 | |
| Online Presence | P1 | |
| Темы (dark/light/AMOLED) | P2 | |
| Bot API (discord.js-style SDK) | P2 | |
| Voice/Video (LiveKit) | P2 | |
| Message Search | P2 | |
| Markdown + Syntax Highlighting | P2 | |
| Invite Links | P2 | |
| Server Roles + Permissions | P2 | |
| Auto-admin Handover | P3 | |

### ❌ НЕ берём / переделываем

| Фича EREZ | Решение в Veil |
|---|---|
| **Web-клиент (браузер)** | **Убран. Только Desktop + Mobile** |
| Vanilla JS DOM manipulation | Revolt UI внутри Tauri WebView (desktop), RN (mobile) |
| JS крипто (TweetNaCl) | **Rust native FFI** — ключи не покидают Rust |
| WASM для крипто | **Нет WASM** (кроме share-viewer). Прямой FFI |
| LocalStorage для ключей | **OS Keychain** (macOS Keychain, Android Keystore, Linux Secret Service) |
| 68 WS типов (string-based) | ~25 Protobuf типов (binary), кодируются в Rust |
| SQLite + PG dual mode (server) | Только PostgreSQL (server), SQLCipher (client) |
| PBKDF2 (600K итераций JS) | Argon2id (Rust native) |
| In-memory device state | Redis + PostgreSQL (server), SQLCipher (client) |
| Monolith server.js | Go микросервисы |
| PWA / Service Worker | Нативные push (FCM/APNs), background service |

---

## 7. Структура Репозитория

```
veil/
├── README.md
├── LICENSE
├── docker-compose.yml          # Dev: PostgreSQL + Redis + NATS
├── docker-compose.prod.yml     # Production
├── Makefile                    # Build all targets
│
├── proto/                      # 🔵 Protobuf definitions (ЕДИНЫЙ КОНТРАКТ)
│   └── veil/v1/
│       ├── envelope.proto      # Main message wrapper
│       ├── auth.proto
│       ├── chat.proto
│       ├── share.proto
│       ├── server.proto
│       ├── media.proto
│       └── presence.proto
│
├── crypto/                     # 🦀 veil-crypto (Rust)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── lib.rs
│   │   ├── keys.rs             # BIP39, Argon2id
│   │   ├── ratchet.rs          # Double Ratchet
│   │   ├── x3dh.rs             # X3DH key agreement
│   │   ├── aead.rs             # XChaCha20-Poly1305 + padding
│   │   ├── kdf.rs              # HKDF-SHA256
│   │   ├── signature.rs        # Ed25519
│   │   ├── share.rs            # Secure share encrypt/decrypt
│   │   └── sealed.rs           # Sealed sender
│   └── tests/
│       └── vectors.rs
│
├── client/                     # 🦀 veil-client (Rust) — протокол + sync
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── connection.rs       # WebSocket + TLS pinning
│       ├── protocol.rs         # Protobuf codec
│       ├── sync.rs             # Offline queue
│       ├── sessions.rs         # Ratchet session mgmt
│       └── api.rs              # Public API
│
├── store/                      # 🦀 veil-store (Rust) — SQLCipher + Keychain
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── db.rs               # SQLCipher
│       ├── keychain.rs         # OS keychain
│       ├── models.rs
│       └── migrations.rs
│
├── ffi/                        # 🦀 UniFFI bindings generator
│   ├── Cargo.toml
│   ├── uniffi.toml
│   └── veil.udl               # Interface definition → Kotlin/Swift/TS
│
├── desktop/                    # 🖥 Tauri v2 Desktop App
│   ├── src-tauri/
│   │   ├── Cargo.toml          # deps: veil-crypto, veil-client, veil-store
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── commands.rs     # IPC bridge (thin wrappers)
│   │   │   ├── tray.rs
│   │   │   ├── pinning.rs      # TLS cert pinning
│   │   │   └── updater.rs      # Ed25519-signed auto-update
│   │   └── tauri.conf.json
│   ├── src/                    # UI (React/Solid inside WebView)
│   │   ├── App.tsx
│   │   ├── components/
│   │   ├── stores/             # UI state only, no secrets
│   │   ├── hooks/
│   │   └── i18n/
│   ├── package.json
│   └── vite.config.ts
│
├── mobile/                     # 📱 React Native
│   ├── App.tsx
│   ├── src/
│   │   ├── screens/
│   │   ├── components/
│   │   ├── stores/
│   │   ├── i18n/
│   │   └── native/
│   │       └── VeilModule.ts   # JSI type definitions
│   ├── native/                 # Rust → JNI/Swift
│   │   ├── Cargo.toml
│   │   ├── src/lib.rs
│   │   ├── build-android.sh
│   │   └── build-ios.sh
│   ├── android/
│   ├── ios/
│   ├── app.json
│   └── package.json
│
├── server/                     # 🔷 Go backend (monorepo)
│   ├── go.mod
│   ├── cmd/
│   │   ├── gateway/
│   │   ├── chat/
│   │   ├── auth/
│   │   ├── media/
│   │   ├── share/
│   │   ├── presence/
│   │   ├── voice/
│   │   ├── push/
│   │   └── allinone/           # Single-binary for self-hosting
│   ├── internal/
│   ├── pkg/
│   ├── migrations/
│   └── Dockerfile
│
├── share-viewer/               # 🔗 Lightweight web page (ЕДИНСТВЕННЫЙ web-компонент)
│   ├── index.html              # Self-contained, inline JS
│   └── veil-crypto-mini.wasm   # Только decrypt + Argon2id (~50KB)
│
├── sdk/                        # 🤖 Bot SDK
│   ├── go/
│   ├── python/
│   └── js/
│
├── shared/                     # 📦 Shared assets
│   ├── i18n/                   # EN/RU translations
│   ├── theme/                  # Color tokens
│   └── types/                  # Generated TS types from UniFFI
│
├── deploy/                     # 🚀 Deployment
│   ├── docker/
│   ├── kubernetes/
│   ├── nginx/
│   └── scripts/
│
└── docs/
    ├── architecture.md
    ├── crypto-spec.md
    ├── protocol.md
    ├── self-hosting.md
    └── threat-model.md         # Модель угроз (native-only)
```

---

## 8. Фазы Разработки

### Phase 0: Rust Foundation (2-3 недели) ✅ DONE
- [x] Создать monorepo, Cargo workspace (crypto + client + store + ffi)
- [x] `veil-crypto`: keys (BIP39, Argon2id), AEAD (XChaCha20), signatures (Ed25519)
- [x] `veil-crypto`: тесты + RFC test vectors
- [x] `veil-crypto`: zeroize on drop, mlock для key material
- [x] `proto/`: Protobuf definitions (envelope, auth, chat, presence)
- [x] `veil-store`: SQLCipher wrapper, keychain integration (keyring crate)
- [x] CI: GitHub Actions (cargo test, clippy, fmt, cargo-audit)

### Phase 1: Protocol + Server MVP (2-3 недели) ✅ DONE
- [x] `veil-crypto`: Double Ratchet + X3DH + тесты
- [x] `veil-client`: WebSocket + TLS cert pinning + Protobuf codec
- [x] `veil-client`: offline queue, reconnect logic
- [x] `server/cmd/gateway`: Go WebSocket server
- [x] `server/cmd/auth`: Ed25519 challenge-response
- [x] `server/cmd/chat`: store-and-forward DM delivery
- [x] PostgreSQL migrations, Docker compose
- [x] UniFFI: `.udl` definition, Kotlin/Swift/TS bindings generation

### Phase 2: Desktop App (3 недели) ✅ DONE
- [x] Tauri v2 scaffold, Cargo deps on veil-* crates
- [x] Tauri commands: auth, send/receive, conversations
- [x] UI: Auth screen (BIP39 mnemonic entry, PIN setup)
- [x] UI: Conversation list + DM chat (custom SolidJS)
- [x] PIN lock / auto-lock (Argon2id async + spawn_blocking)
- [x] System tray, notifications, deep links
- [x] Encrypted local DB (SQLCipher via veil-store)
- [x] Island layout (4 animated cards: rail, sidebar, chat, members)
- [x] Standardized ContextMenu component (Kobalte, WAI ARIA)
- [x] Context menu on messages (copy, delete)
- [x] Hebrew rain lock screen with stagger animations
- [x] **Первый работающий DM чат Desktop ↔ Desktop**

### Phase 3: Mobile App (3-4 недели) ⚠️ IN PROGRESS
- [x] React Native bare workflow (no Expo — нужен JSI)
- [ ] Rust JNI bridge (Android) + Swift bridge (iOS)
- [x] Auth flow (BIP39, PIN, biometrics)
- [ ] DM chat (same protocol as desktop)
- [ ] Push notifications (FCM/APNs via veil-push)
- [ ] Android Keystore / iOS Keychain integration
- [ ] Background WebSocket (foreground service Android)
- [ ] **Первый работающий DM: Desktop ↔ Mobile**

### Phase 4: Groups & Servers (3 недели) ⚠️ IN PROGRESS
- [x] `veil-crypto`: Sender Keys for groups (SenderKeyState, distribution, wire format)
- [x] `veil-store`: group_members + sender_keys_local tables, CRUD
- [x] `server/cmd/chat`: group REST endpoints, fan-out, sender key distribution WS
- [x] Tauri commands: create_group, add/remove/get group members
- [x] Desktop UI: sidebar tabs (All/DMs/Groups), new group dialog, group avatars
- [x] Desktop UI: group member panel (Island 4) with slide animation
- [ ] Server/Channel model (channels inside servers)
- [ ] Role/Permission model (PostgreSQL + UI)
- [ ] Desktop UI: server rail, channel list, role management
- [ ] Group encryption key rotation on join/leave
- [x] Desktop: message replies, edits, delete
- [x] Desktop: delete animation, message length limit (4000 chars)
- [x] Desktop: markdown rendering (bold, italic, code, links, spoilers)
- [x] Desktop: typing indicators, read receipts
- [x] Desktop: big emoji (1-3 emoji-only messages rendered large)
- [x] Desktop: reactions (emoji quick-pick in context menu, reaction pills)
- [ ] Mobile UI: servers, channels (native navigation)

### Phase 5: Secure Shares (1-2 недели) ⚠️ IN PROGRESS
- [ ] `server/cmd/share`: CRUD, TTL, view counter, auto-purge, password rate-limit
- [x] `share-viewer/`: minimal web page + veil-crypto-mini.wasm
- [ ] Desktop: create share from chat, QR code
- [ ] Mobile: create/view share, QR scanner
- [ ] Password protection (Argon2id)

### Phase 6: Multi-Device + Polish (2-3 недели)
- [ ] Device linking (QR code scan between devices)
- [ ] Message sync across devices (fan-out encryption)
- [ ] Desktop: themes (dark/light/AMOLED), emoji fingerprint verification
- [ ] Mobile: themes, fingerprint verification
- [ ] Desktop builds: `.deb`, `.AppImage`, `.dmg`, `.msi`
- [ ] Mobile builds: Play Store, App Store, F-Droid

### Phase 7: Voice + Advanced (4+ недели)
- [ ] LiveKit integration (voice/video calls)
- [ ] Bot SDK (Go/Python/JS)
- [ ] Message search (client-side FTS on SQLCipher)
- [ ] View-once photos
- [ ] Disappearing messages
- [ ] Reactions, replies, edits, forwarding
- [ ] Sealed sender (hide sender metadata from server)

---

## 9. Модель Угроз (Native-Only Advantage)

### Атаки, которые мы БЛОКИРУЕМ (vs Web-клиент)

| Атака | Web-клиент (EREZ) | Native (Veil) |
|---|---|---|
| **XSS** → кража ключей | ⚠️ Уязвим: ключи в JS heap | ✅ Невозможно: ключи в Rust, нет DOM |
| **Расширение браузера** → сниффинг | ⚠️ Читает DOM, localStorage | ✅ Нет расширений |
| **DevTools memory dump** | ⚠️ Любой пользователь ПК | ✅ Process memory protected, mlock |
| **CDN compromise** → подмена JS | ⚠️ Серверу доверяем при каждом открытии | ✅ Бинарник подписан Ed25519, reproducible builds |
| **MITM при загрузке** | ⚠️ HSTS помогает, но не 100% | ✅ Certificate pinning, TLS 1.3 only |
| **Cold boot attack** | ⚠️ Ключи в JS heap (не зануляются) | ✅ zeroize-on-drop + mlock |
| **Скриншот/screen capture** | ⚠️ Нет защиты | ✅ FLAG_SECURE (Android), нет скриншотов |
| **Clipboard sniffing** | ⚠️ document.execCommand доступен | ✅ Native clipboard с таймером |
| **Keylogger в браузере** | ⚠️ JS keylogger в расширении | ✅ Нативный ввод, нет JS доступа |

### Атаки, от которых защищаемся на уровне протокола

| Атака | Защита |
|---|---|
| **Compromised server** | Zero-knowledge: сервер не видит plaintext |
| **Сompromised device** | Forward secrecy: Double Ratchet обновляет ключи каждое сообщение |
| **Future key compromise** | Post-compromise security: новый DH ratchet step после компрометации |
| **Metadata analysis** | Sealed sender: сервер не знает отправителя |
| **Replay attack** | Sequence numbers + message keys used once |
| **Key impersonation** | Ed25519 подписи + emoji fingerprint verification |

---

## 10. Deployment (Day 1: Simple)

```yaml
# docker-compose.yml — минимальный продакшн
services:
  gateway:
    build: ./server
    command: ["/app/veil-allinone"]
    ports:
      - "443:8080"
    environment:
      - DATABASE_URL=postgres://veil:secret@db/veil
      - REDIS_URL=redis://redis:6379
      - NATS_URL=nats://nats:4222
    depends_on: [db, redis, nats]

  db:
    image: postgres:17-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=veil
      - POSTGRES_USER=veil
      - POSTGRES_PASSWORD=secret

  redis:
    image: redis:7-alpine

  nats:
    image: nats:2-alpine
    command: ["--jetstream"]

  share-viewer:
    build: ./share-viewer
    ports:
      - "8081:80"

volumes:
  pgdata:
```

---

## 11. Ключевые Метрики (Цели)

| Метрика | EREZ Secret | Veil (цель) |
|---|---|---|
| Время генерации ключей (mobile) | 2-3 сек (JS PBKDF2) | < 200ms (Rust Argon2id native) |
| Шифрование сообщения | ~5ms (JS NaCl) | < 0.05ms (Rust ChaCha20 native) |
| Double Ratchet step | ~10ms (JS) | < 0.3ms (Rust native) |
| Key storage | localStorage (plaintext!) | OS Keychain + SQLCipher |
| Memory protection | Нет (JS GC) | mlock + zeroize-on-drop |
| Attack surface (client) | XSS, extensions, devtools | Native binary only |
| WebSocket типов | 68 (string JSON) | ~25 (binary protobuf, Rust codec) |
| Backend LOC | 22,600 (monolith) | ~2,000 per Go service |
| Frontend LOC | 8,440 (vanilla JS) | Component-based (Tauri/RN, UI only) |
| Max concurrent connections | ~5K (Node.js) | 100K+ (Go goroutines) |
| Cold start (mobile) | 3-5 сек | < 0.5 сек (precompiled Rust) |
| Offline support | Нет (WS-only) | SQLCipher, full offline read/compose |
| Push notifications | Нет | Нативные FCM/APNs |

---

## 12. Открытые Вопросы

1. **Название**: Veil? Bastion? Aegis? Phantom? Твой вариант?
2. **Лицензия**: MIT (максимальная свобода) или AGPL (защита от закрытых форков)?
3. **Desktop UI framework**: Revolt fork (Solid.js) или custom React/Svelte?
4. **Федерация**: Планируется ли общение между разными серверами?
5. **Монетизация**: Self-hosted only или будет managed SaaS?

---

## 13. Первый Шаг

```bash
mkdir -p veil/{proto/veil/v1,crypto/src,client/src,store/src,ffi,desktop,mobile,server,share-viewer,shared,deploy,docs}
cd veil
git init

# Cargo workspace
cat > Cargo.toml << 'EOF'
[workspace]
members = ["crypto", "client", "store", "ffi"]
resolver = "2"
EOF

# Начинаем с crypto — это фундамент
cd crypto && cargo init --lib --name veil-crypto
cargo add x25519-dalek ed25519-dalek chacha20poly1305 hkdf sha2 argon2 bip39 rand zeroize
```

> *"Ключи не покидают Rust. Никогда."*
