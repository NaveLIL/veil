# Phase 4P — Device Push Security Review

Дата: 2026-07-14

## Исправленный транспортный контракт

Повторный аудит по актуальной Android UnifiedPush specification обнаружил,
что прежний endpoint-only/XChaCha transport несовместим с современным
connector: distributor выдаёт RFC 8291 subscription с `p256dh` и `auth`, а
application server обязан отправлять `Content-Encoding: aes128gcm`.

Migration 025 выполняет pre-release hard cutover:

- удаляет все endpoint-only строки — production-пользователей ещё нет;
- требует валидные P-256 public key и 16-byte auth secret;
- допускает fan-out только после challenge/confirmation;
- не содержит legacy/plaintext/custom-envelope fallback.

Gateway использует RFC 8291 Web Push и RFC 8292 VAPID. VAPID private key
остаётся только в server configuration; Android получает только public key.
Если VAPID не настроен, новая регистрация и delivery fail closed.

## Privacy contract

Обычный push содержит только `{"v":1,"type":"wake"}`. Web Push record всегда
имеет размер 2048 bytes, поэтому distributor не получает message length,
conversation id, sender id, display name, message id или ciphertext preview.
После wake-up клиент выполняет обычный authenticated E2E sync.

Challenge содержит случайный 256-bit token внутри такого же 2048-byte encrypted
record. Пока клиент не вернул token подписанным запросом текущего account/origin,
subscription не попадает в dispatcher projection. Это ограничивает SSRF/DoS
amplification через произвольные push endpoints.

Endpoint URL является bearer capability. List API возвращает только origin,
label, policy и validation status; endpoint path, `p256dh` и `auth` обратно в
desktop renderer не выдаются. Production logs используют только HMAC reference.

## Client boundary

Desktop только просматривает, выключает, временно заглушает и удаляет mobile
bindings. Ручной ввод endpoint удалён: endpoint и Web Push keys создаёт Android
UnifiedPush connector с private material в Android Keystore.

Android registration/receiver требует production native identity/auth runtime:

1. signed current-origin GET VAPID public key;
2. connector registration с VAPID и account-scoped instance id;
3. signed POST полного subscription;
4. получение и signed confirmation challenge;
5. generic notification и bounded sync только для текущего native binding;
6. unregister/cancel при account switch, logout или origin change.

До появления этой native границы Expo dev mock не имеет права регистрировать
push: он использует фиктивные ключи и не является security boundary.

## Остаток Phase 4P

- server Web Push/VAPID/capability validation: реализовано;
- desktop policy/device management: реализовано;
- Android connector receiver: блокируется Phase 5A native crypto/auth runtime;
- iOS APNS extension/App Group: отдельный iOS foundation;
- physical distributor/device matrix: обязательна перед production release.
