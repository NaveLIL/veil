# Реализация надёжности Veil: подтверждённые результаты

Дата: 4 октября 2026 года. Исходная база исследования: `e9f020c5332b892feeec20313c239795e0587bd4`.

Это отчёт о реально выполненных изменениях и проверках, а не отметка о завершении всей [дорожной карты](../roadmaps/backend-and-mobile-reliability-2026-10-04.md).

Последнее host evidence находится в разделе «Финальные host gates перед tester
packaging» ниже. Ранние разделы сохраняют исходные ограничения окружения и
результаты отдельных этапов. R02 исправлен и проверен; R03/R04/R13 и M01–M03
имеют выполненный первый объём. Full offline/history/multi-device/group/mobile
release gates остаются открытыми. APK/physical success не выводится из host tests.

## R01: интеграционные проверки — частично реализовано

[Go CI](../../.github/workflows/go.yml) теперь запускает `go test -tags=integration -race -p 1 -timeout 15m -v ./internal/...`. В прежней команде были только `internal/integration/...` и `internal/db`; gateway suites отсутствовали. Охват всех внутренних пакетов включает gateway и будущие tagged suites. Последовательный запуск пакетов ограничивает число одновременно создаваемых PostgreSQL контейнеров.

Добавлены regression-сценарии R02. Сценарии инверсии commit/cursor и одновременной инициации Direct из R01 пока не реализованы этим пакетом; R01 целиком не закрыт.

Локально Docker Desktop не смог запустить Linux engine. Для выполнения assertions использован отдельный PostgreSQL 16.15 cluster на `127.0.0.1:55432`, вне репозитория и без пользовательских данных. Новый [testpostgres helper](../../veil-server/internal/testpostgres/provision.go) сохраняет testcontainers по умолчанию и позволяет указать `TEST_DATABASE_URL` для выделенного локального PostgreSQL. Каждый тест получает новую `veil_integration_<UUID>` database; миграции не применяются к database из URL, а созданная database удаляется при cleanup. Общий helper подключён к DB и REST harness; gateway integration использует тот же REST harness.

Для воспроизведения на выделенном локальном cluster:

```powershell
$env:TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'
go test -tags=integration -count=1 -timeout 3m -v ./internal/db -run 'Test(DeletePopulatedChannelPreservesSendOutcome|ReorderChannelsRejectsWholeBatchAndBroadcastsOnlyCommit)$'
```

Команда выполняется из `D:/repos/veil/veil-server`. Пользователь тестового cluster должен иметь право создавать databases. В CI override не задаётся: остаются disposable containers.

## R02: удаление канала и атомарный reorder — реализовано и проверено

### Подтверждение дефектов исходного кода

Подготовлена изолированная копия сервера в `D:/tmp/veil-r02-baseline-20261004/veil-server`. В ней сохранены новые тесты и инфраструктура, но только тела `db.DeleteChannel` и `servers.Service.ReorderChannels` заменены исходными из HEAD. Общий рабочий каталог для baseline не откатывался.

На PostgreSQL 16.15 оба regression-теста этой копии завершились ошибкой:

- Удаление наполненного канала: `SQLSTATE 23503`, FK `messages_conversation_id_fkey` препятствует удалению conversation.
- Reorder с отсутствующим или чужим вторым каналом: позиция первого канала уже изменена на `20`, несмотря на ошибку всего запроса. Исходный код также принимал duplicate, отрицательную позицию и некорректные category references.

### Изменения

[DB servers](../../veil-server/internal/db/servers.go) сохраняет существующую hard-delete семантику. В одной транзакции блокируются канал и conversation, удаляются prototype MLS записи, реакции и сообщения, затем канал и conversation. Message attachments и остальные зависимости с существующими FK удаляются каскадом. Account-scoped `message_send_idempotency` не удаляется. Upload metadata/blobs сохраняют отдельный retention/cleanup lifecycle; SQL purge не объявляется удалением файлов из backend storage. Дочерние каналы удаляемой категории сохраняются и переходят на верхний уровень.

Reorder перенесён в DB transaction. До записей проверяется весь batch: UUID, дубликаты, позиции, взаимоисключающие category flags, принадлежность каналов/category серверу, тип категории и права. Row locks берутся в порядке отсортированных ID. Server и channel ACL повторно проверяются внутри транзакции, используя одну Serializable snapshot. Для `40001`/`40P01` разрешены максимум три попытки с повторной полной проверкой. [Service](../../veil-server/internal/servers/service.go) публикует возвращённые committed snapshots только после успешного commit.

Новые миграции не потребовались; существующие migration files не изменены. Решение об изоляции и lock order сверено с официальной документацией [PostgreSQL 16: Transaction Isolation](https://www.postgresql.org/docs/16/transaction-iso.html) и [Explicit Locking](https://www.postgresql.org/docs/16/explicit-locking.html). Этот пакет не вводит общий протокол линейного отзыва всех ACL и durable broadcast queue: последняя остаётся зависимостью последующих R11/R12.

### Фактические проверки

[Regression tests](../../veil-server/internal/db/channels_atomic_integration_test.go) в исправленном рабочем каталоге прошли на PostgreSQL 16.15: два top-level теста и восемь subtests, общее время `56.754s`.

- Удаление populated channel с реакцией, attachment и MLS зависимостями.
- Ошибка на последнем этапе purge откатывает предыдущие удаления и не публикует событие.
- После purge точный retry сохраняет message ID, timestamp и roster ACK; конфликтующий digest отвергается.
- Ошибка любого позднего batch item, его ACL или category оставляет ранние позиции неизменными.
- Прямой DB reorder не обходит channel ACL.
- Принудительная ошибка второго UPDATE откатывает первый.
- Broadcast callback видит весь committed batch; rejected batch не публикуется.
- Удаление категории не оставляет dangling references у её существующих детей.
- Два concurrent batches с обратным порядком items заканчиваются одним полным состоянием, без смешивания частей.

Также прошли обычные `go test ./internal/db ./internal/servers`, `go vet ./internal/db ./internal/servers`, tagged compilation DB/REST/gateway, и `go vet -tags=integration ./internal/db ./internal/integration ./internal/testpostgres`.

Локальный запуск `-race` пока не выполнен: текущий Windows Go environment сообщил `-race requires cgo`. Race проверка добавлена в Linux CI; её результат не заявляется как уже полученный. Полный Go/integration прогон после объединения изменений других этапов отражается отдельно ниже.

## R11: River — транзакционный experiment проверен, production R12 не подключён

[Adapter и подробная таблица решения](../../veil-server/internal/delivery/README.md)
используют River/riverpgxv5 **v0.47.0**, upstream commit
`48c0036dcb12b1e2bb65c355593388bb7ff9926e`. Релиз и MPL-2.0 проверены по
[upstream](https://github.com/riverqueue/river/releases/tag/v0.47.0) и
[лицензии выбранной версии](https://github.com/riverqueue/river/blob/v0.47.0/LICENSE).
Точные лицензии transitive modules просмотрены в скачанных модулях; inventory
фиксирует также MVS обновление `golang.org/x/text` до `v0.41.0` и изменения
test-only dependencies. Go 1.26 и pgx v5.10.0 соответствуют нашему серверу.
River Pro и второй движок очереди не добавлены.

Узкая extraction `StoreMessageTx` сохраняет validation/security/reply/upload
логику обычного `StoreMessage`: внешняя pgx transaction принадлежит вызывающему
коду, функция её не коммитит и не откатывает. Для security snapshot требуется
Serializable. Wrapper сохраняет begin/commit и bounded retry. Значения message
ID/timestamp из незавершённой транзакции нельзя публиковать как принятый send.
Production `StoreMessageIdempotent` пока не объединён с delivery intent.

`Producer.InsertTx` проверяет stored message/conversation внутри той же
транзакции и ставит job с двумя UUID references. Job не копирует ciphertext,
plaintext, ключи, username или roster. Handler API требует идемпотентность и
повторную проверку актуальных прав/bindings; experiment worker имеет deadline
10 секунд и bounded retry. Сетевого handler и production fan-out здесь нет.

Миграции experiment закреплены на `SchemaTargetVersion=7`, схеме
`veil_delivery_experiment`; шаги выполняет `rivermigrate.Migrate` отдельными
upstream transactions под bounded advisory coordination, затем Validate.
Повторный запуск проверен. Объединённый `--all` dump не помещён в нашу одну
file transaction: enum/function steps требуют отдельных commit, как описано
в [официальном migration guide](https://riverqueue.com/docs/migrations).
Общий production deployment migrator ещё должен получить этот явный phase;
experiment lock не заменяет его coordination.

Фактический `go test -tags=integration ./internal/delivery -count=1 -v` на
выделенном PostgreSQL 16.15 прошёл за **22.435s**. Два основных теста и четыре
transaction/crash subtests проверяют:

- До commit ни message, ни job не видны другому connection; rollback оставляет ноль обоих.
- Принудительная SQL CHECK ошибка queue insert откатывает message вместе с job.
- Commit публикует одну настоящую `StoreMessageTx` запись и одну job; повтор reference возвращает ту же job, включая retained completed state.
- Настоящий `HandleSendMessageResult` exact retry возвращает прежний message ID, а повторный intent даёт одну job. Это проверки двух существующих boundaries, **не atomic production join** ledger/message/job.
- Child process выполняет идемпотентный SQL effect и завершает процесс через `os.Exit(42)` до River completion. Job остаётся `running`.
- Новый River worker и upstream leader/rescuer восстанавливают ту же job: минимум две attempts и ровно один effect. Тест старит только `attempted_at`, не вручную переводит job в available.
- Shutdown worker bounded; temporary database/schema удаляются helper cleanup. Crash helper штатно skip в parent process и реально запускается child process.

Обычная compilation DB/gateway/cmd/delivery, focused tagged DB/gateway
regressions существующего StoreMessage, `go vet` включая tagged delivery,
`go mod verify`, scoped `git diff --check` и notice generation прошли.
Gateway ещё не линкует adapter: generated notices имеют прежние 28 entries,
runtime allow baseline обновлён только для реально linked x/text. При R12
нужны новый linked inventory и notices. Локальный race для этого experiment
не заявляется: CGO/C compiler отсутствуют.

По проверенным требованиям выбран River как кандидат для R12. Собственный pgx
outbox не введён: причины для fallback на проведённых сценариях не обнаружены.
Это не завершение R12: нужны atomic idempotent path, shared migration phase,
accepted event contract, device-bound push registration, актуальные ACL/expiry,
provider retry и наблюдаемая cleanup policy. Внешний HTTP не объявляется
exactly once; [River](https://riverqueue.com/docs/reliable-workers) допускает
повторную попытку после сбоя. PostgreSQL power loss, push provider и multi-node
WebSocket fan-out этим experiment не проверены.

## R07/R10 и дополнение R01: proposed ADR и commit-order characterization

[ADR-0005](../adr/0005-immutable-events-sync-retention-and-cutover.md) имеет статус
**Proposed**, объединяя authenticated immutable events, watermark/bootstrap,
scoped checkpoints, retention floor и controlled cutover. Он фиксирует
реальные ограничения Direct AD и mutable legacy history, судьбу uncertain
prepared envelope, сохранение identity/trust/transparency и обязательные
review gates. Предложенные численные retention сроки не приняты и не внедрены.
Production event schema/feed R08 и shared native processor R09 не включены.

[Новый actual PostgreSQL test](../../veil-server/internal/db/event_order_experiment_integration_test.go)
прошёл за **13.263s** (один top-level test, три subtests). В настоящем current
history API поздний commit после checkpoint пропускается как `since`, так и
`(created_at, UUID)` cursor, хотя full history содержит сообщение. Отдельная
SQL probe подтверждает commit inversion с BIGSERIAL. Изолированный
conversation counter обеспечивает настоящий row-lock wait следующего writer,
committed watermark, независимое продвижение другой conversation и безопасное
повторное выделение не опубликованного rollback seq.

Это обновляет прежнюю отметку R01: commit inversion теперь **воспроизводится**,
но production исправление ещё не реализовано; concurrent Direct initiation
регрессия этим этапом не закрыта. Counter probe не доказывает совместимость
всего production roster/device/ACL lock graph. Тест создаёт только probe tables
в одноразовой database; production queries/migrations этого этапа не изменены.

```powershell
$env:TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'
go test -tags=integration ./internal/db -run '^TestTimestampCursorMissesLateCommitAndCounterExperimentPreservesOrder$' -count=1 -v
```

Команда выполняется из `D:/repos/veil/veil-server`. Это characterization тест
дефекта и experiment предлагаемого remedy; его зелёный результат нельзя
использовать как доказательство, что нынешний timestamp feed уже исправлен.

## R24a: проверка первого tester APK — bootstrap verifier готов, artifact gate открыт

Пользователь подтвердил отсутствие production certificate и разрешил постоянный
tester key вне репозитория. Independent expected public tester SHA-256:
`f5df868d3f517c0853225840e2c4f67f2d7b20d05b183bf1ab396e530fc3f250`.
Неизвестный production fingerprint не заменён debug или произвольным значением.

[Verifier](../../veil-mobile/scripts/verify-android-tester-apk.mjs) получил явный
локальный режим `--production-certificate-state not-provisioned`, требующий
`--expected-cert-sha256` и независимый `--forbidden-debug-cert-sha256`.
Строгий режим по умолчанию требует production fingerprint; его schema v1 и
[protected CI](../../.github/workflows/mobile-tester.yml) не изменены.
Смешение режимов и неполные/некорректные baselines отвергаются.

Bootstrap использует весь существующий pipeline проверки artifact: exact single
signer, только APK v2 без rotation history, tester package/version/source,
не-debuggable manifest, SDK, permissions/components, privacy/backup/transfer/
recovery/branding, bundled JS и точные arm64-v8a/x86_64 native ABI entries.
Новый JSON schema `veil.android-first-tester-bootstrap-evidence.v1` ограничивает
claim первым tester artifact: `productionSeparationVerified=false`,
`releaseReady=false`, explicit deferred production/release/physical gates.
Он не выдаётся за strict `veil.android-tester-apk-evidence.v1`.

[Verifier tests](../../veil-mobile/scripts/verify-android-tester-apk.test.mjs):
**57/57 PASS** (`node --test`, `151.031ms`). Проверены explicit opt-in, все
обязательные baselines, запрет смешения, wrong/debug signer, multiple signer,
v1/v3/v3.1/v4 rejection, unchanged strict evidence, одинаковые artifact policy
fields в двух schemas, отсутствие ложного production claim и сохранение
source/timestamp/privacy guards. `node --check` обоих scripts и whitespace/
scoped diff checks прошли. Gradle signing/build graph этим этапом не изменён.

[Artifact contract](android-tester-artifact-contract.md) и
[physical prerequisites](android-direct-preview-physical-test-plan.md)
документируют bootstrap и его границы. На момент verifier-проверок фактический
debug keystore отсутствовал и в repo, и в проверенном user Android home.
Baseline для будущего запуска необходимо независимо экспортировать из
настоящего отдельно provisioned debug key; выдуманный fingerprint неприемлем.

Этот раздел не заявляет сборку или успешную проверку готового APK. Их exact
hash/size/certificate/evidence должны быть добавлены после реального build.
Dirty local checkout с HEAD metadata не получает clean-commit CI provenance;
нужен отдельный reviewed source record. Физические matrix cases, Direct ПК ↔
Android, source-clean release gate и production separation ещё не подтверждены.

## Обновление локального evidence после установки toolchain

Ранние ограничения MSVC/CGO выше описывают состояние до установки инструментов.
Теперь MSVC 2022 + Windows SDK, JDK 17, Android SDK/NDK, Perl и C compiler
доступны; они установлены отдельно от source tree, PATH задаётся только процессам.

`cargo test -p veil-store -p veil-client -p veil-ffi --lib --locked` выполнил
**447 тестов PASS**: client 229, FFI 89, store 129. В client остаются 11 прежних
ignored Sender-Key v5 cases; новых skips для этих изменений нет. Отдельный
crossed INITIAL characterization также прошёл (36.57 s): обе одновременно
инициированные сессии не сходятся после restart. Это доказательство открытого
дефекта, поэтому первая физическая отправка должна быть последовательной.

Actual secure/idempotent PostgreSQL reproducer
`TestTimestampCursorCanSkipEarlierStartedLateCommit` прошёл с `-race`
(22.23 s; package 27.188 s). Он использует действующий Direct v2 send path,
а не только legacy StoreMessageTx: cursor пропускает старый timestamp с поздним
commit. R08/R09 всё ещё нужны; зелёный characterization не исправляет feed.

Полный обычный Go `go test -race -timeout 60s ./...` прошёл. Tagged DB,
delivery и gateway suites прошли с `-race` (215.126 / 45.160 / 109.836 s).
Migration upgrade preflights после подключения общего изолированного helper
прошли на PostgreSQL 16.15 (266.640 s). Повторный полный REST integration
выявил panic в `TestChat_AddGroupMember_NonMemberCannotAdd`: fixture не проверял
HTTP response перед использованием id. Теперь prerequisite проверяется с
status/body; точный тест прошёл четыре раза с новой БД и `-race`, но причина
исходного сбоя не установлена. Полный повторный gate пока ожидается.

R04 подключает обычный неизменяемый Direct-текст desktop к существующему
атомарному outbox. Typed acceptance содержит исходные client/local IDs;
блокировка transport после commit не возвращается как отказ. Desktop poller
повторяет bounded pages committed bytes и применяет конечный lost-ACK deadline.
Новый UI regression сохраняет durable receipt при disconnect до IPC return,
а запоздалый callback не очищает изменённый draft или другой UI scope.
Reply/media/TTL и disconnected offline intent не объявлены завершёнными.

Android V2 projection разрешает stable UI ID через durable ACK mapping в одной
SQLCipher snapshot. Native Kotlin/RN передаёт ограниченные проекции и typed
receipt; JS не создаёт domain ID, не хранит ratchet/envelope и не сопоставляет
строки по тексту. R13 переносит подписанный bounded contact HTTP и opaque
actions под native scope/cancellation guards. Production UI использует реальные
адаптированные Rocket.Chat 4.77.0 компоненты; upstream SHA, исходники и MIT
notice перечислены в mobile inventory. Все **30 Jest suites / 262 tests PASS**,
TypeScript и scoped lint прошли. Actual Metro boundary проверил 3193 sources,
включая 11 обязательных production путей и полный MIT notice.

Для tester добавлен явный импорт HTTPS invitation из clipboard: foreground
native Activity проверяет bounded plain-text item и использует прежний parser.
Token/URI не передаются в JS. Нет фонового чтения или автоматического connect.
На веб-странице нужно нажать «Скопировать ссылку»: адресная строка после загрузки
страницы уже не содержит invite fragment. Clipboard пользователь заменяет
самостоятельно; Android не предоставляет атомарный compare-and-clear.

Host release UniFFI DLL, действительный генератор Kotlin bindings и production
surface verifier прошли. APK/EXE находятся на стадии сборки; JVM transport,
обе Android ABI, подпись/manifest финального APK и физический GUI gate ещё
не закрыты этим обновлением. Новая отдельная debug baseline provisioned из
реального keystore; экспортированный certificate SHA-256:
`5218d7331f4ff48a351b65b16d1e2f989fcaf2c56049a4b2c0b5ace67c43335d`.
Production certificate всё ещё не provisioned. Private tester key остаётся
в owner-only каталоге вне repo; пароли и ключ не входят в evidence/source archive.

[Ручная инструкция](pc-android-first-text-test-2026-10-04.md) подготовлена;
она требует два разных аккаунта, по одному устройству, sequential first send.
Настройки внешних witnesses для этого первого существующего режима опциональны;
он не получает Verified claim и не сбрасывает ранее закреплённую trust policy.
Локальные изменения Go не развёрнуты на `https://veil.erez.pro`.

### Финальные host gates перед tester packaging

Полный `go test -tags=integration -race -p 1 -timeout 25m -count=1 -v
./internal/integration` на выделенном PostgreSQL завершился **PASS, 745.183 s**.
Прежний скрытый fixture panic не повторился; это успешный gate с улучшенной
диагностикой, а не доказательство установленной и устранённой причины flake.
CI сохраняет прежний budget 15m: реальный package runtime укладывается в него.

Desktop frontend: **32 suites / 174 tests PASS** при `--maxWorkers=1` с теми
же assertions/timeouts. Параллельный запуск во время cold compilation имел
один 5s timeout существующего dynamic-import теста; последовательный повтор
устранил конкуренцию за ресурсы без исключений тестов. Production Vite build
прошёл с выбранными endpoints `wss://veil.erez.pro/v3/events` и
`https://veil.erez.pro`. `cargo test -p veil-desktop --lib --release --locked`:
**80 PASS**, zero ignored. Tauri release EXE реально собран (31,434,752 bytes);
GUI с пользовательским хранилищем не запускался агентом.

Android Kotlin JVM: debug 200 total / 0 failed / 1 intentional release-only
skip; release 200 total / 0 failed / 15 intentional debug-TLS fixture skips.
Итого **384 выполненных test cases**, число отдельных assert-вызовов не
подсчитывалось. Исходные 11 TLS failures объяснены actual fixture URL:
Windows/Docker reverse DNS давал `kubernetes.docker.internal`, отсутствующий
в SAN локального сертификата. Fixture теперь использует numeric `127.0.0.1`
authority; default hostname verifier и production transport не изменены.
Очистка native buffers проверяется после queue-idle barrier. Native presenceSO
guard исключался только для этих host-only fake-native JVM tests; в APK build
исключений нет.

ARM64 release `libveil_ffi.so` реально собрана (21,212,216 bytes). Вторая ABI,
package verification и clean source record ещё ожидаются. Hash/size финальных
выдаваемых файлов фиксируются отдельным artifact evidence после packaging.
