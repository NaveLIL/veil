# Direct v2: одновременная инициация сессий

Дата: 4 октября 2026 года. Связанные задачи: R01 и R16–R19 из [дорожной карты](../roadmaps/backend-and-mobile-reliability-2026-10-04.md).

## Что подтверждено исходниками

Оба участника новой Direct беседы могут установить initiator session до получения первого сообщения другого участника. Direct v2 transcript включает роли initiator/responder и конкретный X3DH attempt. Поэтому две встречные инициации создают разные `session_id`.

В [api.rs](../../veil-client/src/api.rs) `decrypt_direct_v2_classified` при наличии локальной sticky session сначала вызывает `validate_direct_v2_outer_context`. Противоположная INITIAL-сессия не соответствует существующему session ID и отвергается до установки responder ratchet. В [direct.rs](../../veil-client/src/direct.rs) повторный prekey fetch возвращает `AlreadyEstablished`, когда ratchet уже существует. Перезапуск SQLCipher восстанавливает эти же sticky bindings. Из этого следует риск устойчивой невозможности расшифровать встречные сообщения при сохранённой доступности compose.

Этот вывод относится к надёжности и согласованию сессий. Он не означает успешный обход аутентификации. Текущий отказ сохраняет криптографические ограничения, и удалять их ради расшифрования нельзя.

## Добавленный characterization test

[direct_v2_crossed_initial_tests.rs](../../veil-client/src/direct_v2_crossed_initial_tests.rs) подключён отдельным `cfg(test)` модулем в `api.rs`. Production protocol logic этим изменением не заменяется.

Тест `crossed_initial_attempts_fail_closed_and_remain_nonconvergent_after_restart` строит две отдельные file-backed SQLCipher databases, принимает реальную authenticated directory и выполняет обе initiator installations до любой входящей доставки. Затем через существующий атомарный native outbox подготавливает две INITIAL envelopes при недоступных wire queues.

Проверяются оба встречных отказа, неизменность runtime/durable ratchet, revision, session binding, pending INITIAL и OPK inventory; сохранение точных outbox bytes и client IDs; восстановление после реального закрытия и повторного открытия databases; `AlreadyEstablished` при повторном prekey fetch; повторный отказ после restart.

Это проверка воспроизводимости известного ограничения и сохранения состояния при отказе. Она намеренно не объявляет convergence успешным и не закрывает R01 целиком. Фактический последовательный native Cargo gate на Windows с MSVC завершился успешно: root сообщил о 447 прошедших тестах `veil-store`, `veil-client` и `veil-ffi`, включая новую crossed INITIAL проверку. Генерация реальных UniFFI bindings также прошла; эти результаты не заменяют Android runtime проверку.

## Граница исправления

Перезапись единственного ratchet по правилу «входящий INITIAL побеждает» неприемлема: уже committed ciphertext и idempotency IDs относятся к прежнему session ID. Потерянный ACK или задержанная доставка могут требовать именно этих прежних bytes. Также нельзя автоматически удалить историю/ключи, переупаковать uncertain envelopes или считать серверный ACK доказательством владения сессией адресатом.

Для R16 нужен ADR с выбором session management и сравнением существующего libsignal spike. [Signal Sesame](https://signal.org/docs/specifications/sesame/) прямо рассматривает simultaneous initiation и хранение active/inactive sessions; это подходящий референс, а не готовый протокол совместимости Veil.

Для адаптации такого подхода потребуются:

1. Durable адресация сессии по origin, account/device coordinates и session ID вместо единственного ratchet по account identity.
2. Возможность проверяемо принять вторую responder session, сохранив первую для committed outbox и задержанных authenticated packets.
3. Атомарное сохранение выбранного ratchet transition, OPK consumption, session binding и message projection, без публикации до commit.
4. Проверяемое правило выбора сессии для будущих sends, которое сходится при duplicate/reorder и не переподготавливает старые envelopes.
5. Ограниченные inactive sessions, skipped keys и retention; защита от потока неподтверждённых INITIAL attempts.
6. Явные semantics revoke/link/restore и контролируемая миграция SQLCipher схемы.

Критерий готовности исправления — две начальные envelopes расшифрованы без потери или замены committed bytes, последующий обмен сходится, и те же свойства сохраняются при opposite delivery order, duplicate, lost ACK, process death и reopen. До принятого решения текущие sticky/epoch проверки остаются обязательными.
