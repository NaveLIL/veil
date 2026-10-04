# Android: VEIL-RUNTIME-999 при открытии найденного контакта

Физический тест пользователя: поиск `user_8c129548` успешен, нажатие на контакт
показывает VEIL-RUNTIME-999; чат не открывается. Это происходит до отправки
сообщения. Предыдущая проблема ARM64 cold launch больше не препятствует поиску.

## Подтверждённая причина

Read-only проверка HTTP access log нужного vhost показала два запроса
`POST /v1/conversations/dm`, оба с HTTP 200. Читались только method/path/status;
request bodies, заголовки авторизации, сообщения, приватные ключи и Access
Passes не выводились. Серверные данные не менялись этой проверкой.

В `veil-client/src/direct.rs::install_authenticated_direct_conversation_v1`
создание Direct синтезировало self/peer members с `username=""`. Общий
конвертер страниц каталога создавал `AccountSnapshot.username=Some("")`.
`veil-store` обоснованно запрещает пустую присутствующую username:
`validate_optional_presentation` требует непустую строку. Ошибка доходила
через Rust/UniFFI до native contact callback, затем до VEIL-RUNTIME-999;
навигация выполняется только после успешной native installation.

Добавлен тест с реальным VeilClient и SQLCipher после успешной установки
пустого authenticated directory. На исходном коде он воспроизвёл отказ:
`account username is empty, oversized, or contains control characters`.
Это воспроизведение реального storage path, а не fake session JVM test.

## Исправление и защита

Create-DM response сообщает ID и публичные ключи; сведений о профиле в нём нет.
Новый account snapshot представляет отсутствующую presentation как `None`.
Если уже есть admitted snapshot с точным origin/user/identity/signing tuple,
он сохраняется целиком: неизвестные данные не стирают существующий профиль,
в том числе unversioned username/display name. Если ключи отличаются, старый
snapshot не подставляется вместо нового candidate: проверки несовместимости
и quarantine продолжают действовать.

Store validators, профильные merge/continuity правила, peer key comparison,
native lease/generation authority, SQLCipher, X3DH/Direct v2 и FLAG_SECURE не
ослаблялись. Имена из JavaScript не передаются в Rust как доверенные данные.
Синтетический create path отделён от валидатора настоящих directory pages,
где username по-прежнему обязательна и не может быть пустой.

Независимый read-only разбор цепи JS/Kotlin не выявил дополнительного
детерминированного отказа create/getSnapshot/hydrate/select/navigation.
Он выявил риск стирания unversioned profile при простом переходе на None;
исправление сохраняет точный существующий snapshot и проверяется отдельной
регрессией для unversioned/versioned профилей и повторного открытия Direct.

## Проверки

`cargo test -p veil-client --lib --release --locked direct::tests::`:
**18 PASS**, 0 failed/ignored; включая три новых теста: отсутствующая
presentation, сохранение профиля/повторное открытие, отказ при замене peer
identity. Исходный regression test до исправления: 1 FAIL, ожидаемая причина
empty username. Успешный физический обмен пока не подтверждён.

Нужна новая реальная Rust-библиотека для обоих Android ABIs и APK с повышенной
версией `0.1.0-tester.20261004.3` / `2026100403`, прежним tester-сертификатом
и application ID. Установка обновлением поверх текущего приложения, без
удаления/очистки данных. Работающий Desktop EXE не пересобирается. После
обновления повторить поиск, открыть контакт, отправить первое сообщение
с телефона и дождаться его на ПК, затем ответить с ПК.

Этот документ не утверждает готовность production release или выполнение
остальной backend/mobile дорожной карты.
