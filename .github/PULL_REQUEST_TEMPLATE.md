## Что изменено / What changed

<!-- Кратко опишите проблему и результат. Describe the problem and outcome. -->

## Scope

<!-- Какие компоненты затронуты и что намеренно не входит в PR? -->

## Security, privacy, compatibility

<!--
Укажите влияние на crypto, identity/origin, protocol, ACL, storage, logs,
migrations, deployment/release и обратную совместимость. Напишите "None",
если влияния действительно нет, и объясните почему.
-->

## Проверки / Validation

<!-- Перечислите точные команды и результаты. Не пишите просто "tests pass". -->

- [ ] git diff --check
- [ ] Релевантные автоматические тесты выполнены
- [ ] UI проверен визуально и с клавиатуры, если применимо
- [ ] Migration/rollback проверены, если применимо

## Evidence

<!--
Ссылки на Issue/ADR/review, очищенные логи или скриншоты тестовых данных.
Do not include secrets, recovery material, real messages, or personal data.
-->

## Checklist

- [ ] PR небольшой, сфокусированный и не содержит несвязанных dependency updates
- [ ] Нет секретов, локального .env, build artifacts или несаницированных логов
- [ ] Изменение не добавляет plaintext/weak crypto fallback
- [ ] Контракты и документация обновлены, если поведение изменилось
- [ ] Pre-release статус описан честно; PR не заявляет внешний аудит
- [ ] Я имею право предоставить вклад на условиях AGPL-3.0-or-later
- [ ] Сторонние материалы сохраняют авторство и лицензионные notices
