# Android ARM64: ошибка VEIL-SETUP-002 до регистрации

Пользователь подтвердил, что ПК работает, а Galaxy S26 Ultra показывает
VEIL-SETUP-002 сразу после открытия приложения. Точная версия Android и errno
телефона не получены. Скриншоты заблокированы штатной защитой приложения.

## Дефект и доказательства

Проверен именно выданный APK версии `0.1.0-tester.20261004.1`, исходники
`775e3bf407f76b090d5fb23d6e6881b70e74f3b5`, SHA-256
`994d6cdd3a8598efb4c6459612d70da41a140fd566587a670711c91556b34d47`.
DEX содержит реальные методы React Native bridge: версия с потерянным из-за R8
методом не подтверждается.

`NativeIdentitySetupJournal.readOrNull()` захватывает файловую блокировку и
синхронизирует каталог **до** проверки отсутствия журнала. Поэтому операция
выполняется и при первом запуске без аккаунта. В `syncDirectory()` APK передаёт
в `Os.open()` числовую маску `0xb0000`.

В коде были ошибочно объявлены универсальными значения O_DIRECTORY=0x10000 и
O_NOFOLLOW=0x20000. По заголовкам установленного NDK 27.1.12297006 и результату
clang preprocessing для Android API 24:

| Флаг | arm64-v8a | x86_64 |
| --- | --- | --- |
| O_DIRECTORY | 0x4000 | 0x10000 |
| O_NOFOLLOW | 0x8000 | 0x20000 |
| O_DIRECT | 0x10000 | 0x4000 |
| O_CLOEXEC | 0x80000 | 0x80000 |

На ARM64 прежняя маска содержит O_DIRECT, а нужных O_DIRECTORY/O_NOFOLLOW нет.
Это конкретный дефект ABI; он соответствует месту и времени сообщённого сбоя.
Фактический errno на телефоне не измерен, поэтому диагноз причины сообщения
остаётся обоснованным выводом по коду, а не результатом телефонной трассировки.

Первичные источники: [Android ARM64 UAPI fcntl.h](https://android.googlesource.com/platform/bionic/+/cf02614a4bef8fe336cae8796df5cb6eeb368a6d/libc/kernel/uapi/asm-arm64/asm/fcntl.h),
[Android generic UAPI fcntl.h](https://android.googlesource.com/platform/bionic/+/77f91c6/libc/kernel/uapi/asm-generic/fcntl.h),
[публичный контракт OsConstants](https://developer.android.com/reference/android/system/OsConstants).

## Исправление

Все открытия файлов журнала используют архитектурно корректный публичный
`OsConstants.O_NOFOLLOW` (API 21). Публичного O_DIRECTORY в Android API нет:
для двух разрешённых ABIs он вычисляется закрытым отображением фактического
платформенного O_NOFOLLOW. Неизвестное значение приводит к блокирующей ошибке.
`Build.SUPPORTED_ABIS` не используется: список поддерживаемых устройством ABIs
не определяет архитектуру текущего процесса.

O_CLOEXEC остаётся подтверждённым для обоих ABIs числом 0x80000: публичное поле
доступно с API 27, тогда как минимальная версия приложения — API 24.
Сохранены kernel O_DIRECTORY, O_NOFOLLOW, режим 0600, lstat/fstat, эксклюзивная
блокировка, fsync файлов и каталогов, атомарная публикация и проверка чтением.
Ошибки не превращаются в отсутствие журнала. FLAG_SECURE, шифрование и EXE
не изменены.

## Проверки и установка

Добавлены JVM регрессии для обеих ABI-масок, отсутствия ошибочного ARM64
O_DIRECT/O_LARGEFILE и отказа на неизвестной раскладке. Добавлены instrumentation
проверки настоящих Android syscalls: первое чтение отсутствующего журнала,
запись/повторное чтение/терминальная очистка, отказ при символьной ссылке
на lock-файл. Телефонные instrumentation тесты не запускались; подключённые
тесты разрешены существующим guard только на одноразовом эмуляторе.

Фактический JVM прогон `testDebugUnitTest` и `testReleaseUnitTest` с фильтром
`io.veil.mobile.recovery.*` завершился успешно: **95 + 95 = 190 test cases**,
нулевые failures/errors/skips, включая все три новые ABI регрессии в каждом
варианте. Gradle: BUILD SUCCESSFUL, 6m 13s. Наличие Rust-библиотек проверялось
штатным build guard; исключений проверок для этого прогона не применялось.

Исправленный tester должен иметь версию `0.1.0-tester.20261004.2` / code
`2026100402`, прежний application ID `io.veil.mobile.tester` и прежний постоянный
tester-сертификат. Установка выполняется **обновлением поверх приложения**:
не удалять приложение и не очищать его данные. Работающий EXE остаётся прежним.

После независимой проверки APK требуется ручное подтверждение пользователя:
исчезла ли ошибка холодного запуска и доступен ли экран регистрации. Проверка
на физическом телефоне и реальный обмен ПК ↔ Android пока не подтверждены.

## Фактически собранное обновление

Исходники APK: `3170508d02ec3cb7a9c1d095fe61c821e3942588`, чистое дерево перед
сборкой и упаковкой. Документ дополнен результатами после сборки; изменение
документации не требует пересборки исполняемого приложения.

`assembleInternalTester` и `compileDebugAndroidTestKotlin`: BUILD SUCCESSFUL,
3m 23s. Connected/device tasks не запускались. Применён прежний локальный
адаптер запуска Java Prefab для закреплённого AGP 8.8.2: один подтверждённый
host-only receipt, те же executable/arguments/exit semantics, без изменения
Windows policy, APK guards или runtime защиты. Это не штатная конфигурация AGP
и не утверждение о воспроизводимости CI.

APK: `target/android-update-20261004/3170508d02ec/Veil-Android-0.1.0-tester.20261004.2.apk`,
98,021,906 bytes; SHA-256
`62a5f5d4b17ffd189772e0119bcd41d485d5e907c143a67d87793e094d976a91`.
Независимый verifier подтвердил сертификат, package ID, version/source metadata,
два ABI, строгий manifest/component/permission contract и backup exclusions.
Tester certificate SHA-256 остался
`f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`.
Production certificate не provisioned; `releaseReady=false`.

В DEX фактического APK повторно проверены пять `Os.open` с runtime O_NOFOLLOW,
закрытая directory mapping, lstat/fstat/fsync/close, ReactMethod bridge,
FLAG_SECURE до регистрации и `ALLOW_READY_SCREEN_CAPTURE=false`. Независимое
read-only ревью подтвердило те же свойства. Hermes bundle и оба упакованных
stripped Rust SO совпадают с соответствующими выходами сборки; все 36 project
sources в source map совпали с исходниками, полный Rocket.Chat MIT notice
присутствует в Hermes. Реальный NDK clang отдельно подтвердил обе таблицы flags.

Набор обновления: `target/Veil-Android-Update-3170508d02ec.zip`, 49,608,303 bytes,
SHA-256 `ab0d27dda31f5543e96bbcc7adde0153935b4bec36a2d74b26ebc7a6e6f2eacb`.
Содержит APK, точный AGPL source archive, public certificate, verifier evidence,
build/DEX/ABI proof и исходники build helpers. После упаковки все **33 payload
checksums** повторно проверены чтением ZIP. Private key/password/identity/Access
Pass туда не включены.

EXE не пересобирался и не изменялся; SHA-256 прежней выдачи повторно совпал:
`ff5cb334f4faffb7204463f84023c7af666a685bcfd19953bae809e034688ffb`.
Пользователь сообщил об успешной работе ПК. Повторный запуск нового APK на
Galaxy и обмен между двумя клиентами остаются ручными непроведёнными проверками.
