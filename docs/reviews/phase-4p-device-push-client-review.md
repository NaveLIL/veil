# Phase 4P — Device Push Client Review

Дата: 2026-07-14

## Решение

Phase 4P разделён по реальной границе runtime, а не по интерфейсным экранам.

- Desktop management реализован: пользователь может просмотреть, добавить и
  удалить UnifiedPush endpoints текущего origin/account.
- Полный endpoint является bearer capability. После POST он очищается из DOM;
  list-команда возвращает renderer только host hint, label, timestamps и opaque
  numeric id. Секретный path повторно в WebView не попадает.
- Все операции подписаны текущей identity, привязаны к подтверждённому
  `origin + binding generation` и повторно проверяются после network await.
- Push content остаётся generic: UI и OS notification не получают sender name,
  message text, identity keys или decrypted preview.
- Migration 024 добавляет server-enforced enabled/muted-until policy. Dispatcher
  читает только active/unmuted projection; отключённый endpoint не получает даже
  wake-up timing metadata.

## Почему `K_push` preview не включён

Текущий gateway создаёт metadata-only wake-up и заворачивает его server-side
transport key перед отправкой в ntfy. Этот ключ нельзя поставлять приложениям:
общий server secret в desktop/mobile bundle разрушил бы границу доверия.

Устройство не обязано открывать этот envelope для безопасного v1 workflow:
сам факт доставки от выбранного distributor запускает generic notification и
sync после unlock. Preview можно включить только после отдельного v2 review, где
sender device создаёт inner ciphertext под device-scoped `K_push`, а gateway и
distributor никогда не получают ключ.

## Mobile disposition

Android/iOS receiver нельзя честно объявить готовым поверх текущего
`veil-mobile`: в нём ещё нет production native crypto/identity bridge,
authenticated server session или background sync runtime. Подключение внешнего
connector сейчас создало бы кнопку без способа безопасно подписать endpoint и
синхронизировать сообщения.

Дополнительно проверено 2026-07-14:

- UnifiedPush официально предоставляет Android Kotlin connector;
- React Native/Expo интеграция `expo-unified-push` является third-party и
  Android-only;
- iOS требует отдельного APNS/notification-extension lifecycle и App Group
  keychain; Android API нельзя выдавать за кроссплатформенную реализацию.

Поэтому Android receiver/register lifecycle входит в Phase 5A native runtime,
а iOS extension — в соответствующий iOS foundation. До этого desktop может
управлять endpoint, созданным distributor, но приложение не обещает mobile
preview или background decrypt.

## Обязательные инварианты следующего среза

1. Endpoint создаётся distributor API и никогда не логируется/аналитируется.
2. Регистрация на gateway выполняется только подписанным current-origin REST.
3. До unlock уведомление строго нейтральное: `New message in Veil`.
4. Полученный payload не парсится как доверенный JSON и не влияет на routing;
   он только будит bounded sync текущего подтверждённого origin.
5. Replay/dedup хранится нативно по subscription/message counter; renderer не
   является security boundary.
6. Lock/account switch удаляет in-memory push keys и отменяет background work.
7. DND/mute применяется до dispatcher fan-out на сервере, а не только в UI.
