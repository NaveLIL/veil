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

## Выданное обновление

APK source commit: `ff6e2222be343f6c17dfc3002b9d5f5accc608e0`, чистое дерево
перед native build, APK build и packaging. Этот раздел добавлен документационным
изменением после упаковки; исходники самого APK остаются на указанном commit.

Дополнительный прогон `cargo test -p veil-ffi --lib --release --locked mobile_direct_`:
**49 PASS**, 0 failed/ignored. Итого 67 Rust test cases для shared Direct и
mobile Direct FFI. Focused JS tests ContactSearchScreen/runtimeContacts:
19 PASS, обе suites; они проверяют UI/DTO/correlation, а Rust install в них
mocked. Production UniFFI surface verifier подтвердил прежнюю high-level
secret-safe границу; интерфейсы не изменялись, регенерация Kotlin не требовалась.

Реальный cargo-ndk release build завершён для обеих ABIs с одинаковым чистым
source commit до/после сборки. SHA-256 исходных Rust SO:

| ABI | SHA-256 |
| --- | --- |
| arm64-v8a | `6e75215808bf0584ce14f0647b4f7071ae06894188feaa4867fdf9e301f73f9b` |
| x86_64 | `76f982c5a826d50fe9da0b8a789043d448a2aabe3f87fa51593b38210acedfb0` |

`assembleInternalTester` и `compileDebugAndroidTestKotlin`: BUILD SUCCESSFUL,
2m 23s, с прежним узким локальным AGP host adapter, без пропуска APK guards.
Instrumentation не запускалась на телефоне или эмуляторе.

APK: `target/android-update-20261004/ff6e2222be34/Veil-Android-0.1.0-tester.20261004.3.apk`,
98,038,286 bytes; SHA-256
`cd15d91bc270c1fbf7eefd23bd46e9a5f0850fdc8782634e1c64546cc5a61501`.
Независимый verifier подтвердил постоянный tester certificate, source/version,
package/ABI, строгий manifest/privacy/backup contract. `releaseReady=false`;
production certificate по-прежнему не provisioned. DEX inspection подтвердил
сохранение прежнего ARM64 journal fix, ReactMethod и FLAG_SECURE.

Обе новые Rust SO отличаются от предыдущей выдачи; merged native input совпал
с actual cargo-ndk output, packaged stripped SO — с AGP stripped output.
Проверено содержимое ZIP/APK, а не только промежуточные файлы. Hermes bundle
совпал с generated bundle; 36 project sources в source map совпали с исходниками,
полный Rocket.Chat MIT notice сохранён.

Набор: `target/Veil-Android-Update-ff6e2222be34.zip`; SHA-256
`8d0a126aee74a3fdd9209b922207c7d9ddf9a526fe9709f0fd72803c905b7fd1`.
Включает точный AGPL source, public tester certificate, APK evidence,
Rust build/source/output receipts, ожидаемое baseline failure и успешные
test logs. Приватные ключи, пароли, recovery phrase, Access Pass и сообщения
не включены. Успешный обмен телефона с ПК остаётся ручной проверкой пользователя.
