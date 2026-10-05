# Veil mobile: историческая контрольная точка Live 09

Этот документ фиксирует предыдущий Live 09. Актуальный результат автономной сессии, release без Metro, Android accessibility и source integration Direct: [Design 10](mobile-frontend-offline10-2026-10-05.md).

Утверждённые острова, док, пять тем, профиль и жест перекрытия чатом сохранены. Работа только в изолированном Design Live с вымышленными данными; native/Rust и production не изменяются.

## Checklist

- [x] Design 08: ответ, системное копирование, ID-цитаты, переход к оригиналу, локальное редактирование и удаление; 64 исходных теста проходят.
- [x] Самостоятельный фиолетовый quote-island; убран переключатель Все/Непрочитанные.
- [x] Физические проверки отмены/удаления/копирования Design 08: черновик Keep08 сохранён после save/cancel; tombstone и его quote не содержат текста; системное копирование подтверждено.
- [x] Плотность delivery: обычный статус в конце серии одинаковых состояний; attention отдельно. 3 теста; на телефоне 5 реплик Даниила с одной строкой «Отправлено».
- [x] Design 09: локальный demo-путь иллюстрация/файл, compact preview/подпись/отмена/прогресс/ошибка/повтор. Физически проверены keyboard, отмена без потери подписи, успех изображения, ошибка файла и повтор без второй карточки. Ответ + вложение + клавиатура проверены и исправлены: на низком viewport оба preview становятся одной строкой, обе отмены остаются доступны.
- [x] Персонализация: local allowlist, atomic preferences и обработанная подложка; hydration до UI. Профиль явно demo. Физическая проверка восстановления темы выполнена отдельно ниже; проверка подложки через picker после перезапуска ещё требуется.
- [x] Типизированная Direct-граница по существующему native контракту; unsupported capabilities явно отсутствуют. Тесты стабильного ID, unknown и unavailable без fallback.
- [x] Финальные проверки кода и Live APK с точной фиксацией mobile-исходников; контрольный комплект указан ниже.

## Решения и границы

`veil-ffi/src/lib.rs:516,676`: Sending/Sent/Failed/Unknown; внутренние 1..=3 намеренно спроецированы в Sent. `veil-mobile/src/native/runtime.ts:76` повторяет этот контракт. Delivered/read не доступны UI: не выдумывать. Fixture accepted означает только «Отправлено». Collapse применяется только к одинаковому accepted и существующему canGroup (тот же автор/день, ≤5 минут). Failed/queued/unknown, неизвестные факты, удалённые сообщения и граница группы сохраняют отдельные статусы. Индивидуальная accessibility label сохраняет факт каждого сообщения.

Настоящий Direct разрешает только текстовую проекцию; reply/attachments/edit/delete не выставлены этим API. Не переносить demo-возможности в настоящий runtime, не добавлять JS outbox.

Не выполнены: TalkBack на устройстве, release-профилирование, iOS, восстановление выбранного фото-фона после перезапуска, полная матрица увеличенного шрифта для всех панелей и сочетания reply + attachment + keyboard (обычный шрифт проверен). Live debug не является доказательством FPS или безопасной реальной переписки. Сообщения/черновики остаются в памяти. Настоящий media picker/upload не подключён: демо-источник указан прямо в панели. Изменён только isolated Android design-host для локального оформления; production native/Rust, секреты и протокол не меняли.

## Проверки

Исходно: чистое дерево на `8bbdf3ff154d9b7182be6a1ce295550be9c93b53`, 64 теста/9 suites. Изменения оставлены проверяемым diff, без нового Git-коммита.

Текущий результат: 79 тестов/14 suites проходят на финальном исходном snapshot; TypeScript, ESLint и AST inventory 35 источников проходят. Команды из `veil-mobile`:

```text
node node_modules/typescript/bin/tsc --noEmit
node node_modules/eslint/bin/eslint.js src/interfacePreview src/presenters/directDesignAdapter.ts src/presenters/__tests__/directDesignAdapter.test.ts --ext .ts,.tsx
node scripts/verify-design-preview-source.mjs
node node_modules/jest/bin/jest.js --runInBand src/interfacePreview src/__tests__/App.runtimeGate.test.tsx src/presenters/__tests__/directDesignAdapter.test.ts
```

Первые 3 падения были проверками старого размера 320 после увеличения fixtures до 720; заменены проверками диапазона 500–1000 и сохранности полного исходного префикса. Один integration-test использовал неотрендеренный хвост Jest FlatList; команды viewer/retry проверяются через feature callbacks, кнопки — отдельным тестом AttachmentCard. Тесты не отключены. Новые сборочные/типовые ошибки устранены; Gradle остаётся с существующими deprecated-feature предупреждениями.

Сборка: isolated `:designPreview:assembleDebug`, tester signing, loopback Metro/ADB reverse. Native APK verifier проверяет подпись, package, permissions, отсутствие account DEX/libs/enrollment, запись clipboard, явную регистрацию preferences и исходный snapshot hash. Это host-adapter сборка Windows, не CI. Для рабочего diff SOURCE_COMMIT означает базу, SOURCE_PATCH_SHA256 — manifest точных mobile-файлов; snapshot сравнивается до/после сборки. APK не выдаётся за чистый commit.

История сохраняет авторскую группировку desktop (`App.tsx`, 5 минут). Последние сообщения и read indicator остаются локальными UI-состояниями. Native delivered/read объединяются в sent самим FFI; UI не знает дополнительных фактов.

Общие pattern: radius 20dp, touch targets 48dp, прежние typography/palettes и motion; новые destructive actions используют semantic danger. Новые modal transitions — native fade/Reduce Motion none, без второй animation библиотеки. Профиль и dock не заменены.

Документация платформ: [React Native 0.79 accessibility](https://reactnative.dev/docs/0.79/accessibility), [Android document access](https://developer.android.com/training/data-storage/shared/documents-files). Эти API учитываются как граница будущего picker; в этой сборке обычные фото/файлы представлены явными fixture assets.

## Последний физический проход

| Проверка | Результат |
|---|---|
| Пять коротких исходящих Даниила | Одна строка «Отправлено» у конца серии; детали каждого сообщения остаются в accessibility label |
| Viewer изображения → Android Back | Изображение открывается с сохранением пропорций; возвращается тот же участок истории |
| Свайп чата вправо и выбор другого диалога | Док, профиль и острова остаются; промежуточный кадр снят с пальцем на экране |
| Шрифт 130% и 150%, с перезапуском на каждом масштабе | Список и чат просмотрены; исправлены обрезанные инициалы/время и placeholder. Инициалы декоративного аватара не масштабируются, основной текст масштабируется. Исходный `font_scale=1.0` восстановлен в finally |
| Unknown у файла | Нет таймера успеха и кнопки повтора; отдельная неопределённость сохранена |
| Ответ + изображение + подпись + keyboard, 100% | Найден и исправлен слишком маленький viewport истории. Preview располагаются рядом на низком экране, отмены доступны; после отправки цитата/подпись/изображение сохранены |
| Восстановление темы | Ocean пережила force-stop/relaunch; для завершения возвращена исходная OLED |

Первый font-scale проход выявил регрессии и не засчитан как успех. Повтор выполнялся с холодным запуском, чтобы исключить устаревшую разметку. На 150% длинное имя в списке сокращается многоточием, время остаётся полным. Это ограниченный smoke, а не полный accessibility audit.

## Контрольный комплект и продолжение

Комплект: `target/design-preview-20261005/61c74ab43140-live09/`. В нём Live APK, manifest хешей mobile-файлов, исходный Git diff + новые файлы, скриншоты, результаты проверок, SHA256SUMS и инструкция. База `8bbdf3ff154d9b7182be6a1ce295550be9c93b53`; snapshot `61c74ab43140a5c5f7e87a053a2e475eac7ecf2813fce382e6fe4d63f4fc9637`. Предыдущий `ff096dc695ea-live09` сохранён как промежуточная точка до исправления комбинированного preview. Live JS загружается из Metro: manifest фиксирует проверенную версию, но последующие изменения через live reload требуют новой контрольной точки. Скриншоты разных проходов имеют отдельное указание native build и UI source snapshot в `PHYSICAL-CHECKS.json`.

Модули выделены по ответственности: delivery presentation; attachment state/transfers, карточка/preview/viewer; preferences bridge/hydration; typed conversation contract и Direct presenter. Используются прежние primitives, общие radius 20dp/targets 48dp/palettes/typography, существующий жест на UI thread и native modal fade с Reduce Motion. Package manager, lockfile и зависимости не менялись.

Компактная комбинация выбирается по измеренному viewport ниже 500dp: не предполагает высоту конкретной клавиатуры и не меняет обычные отдельные preview при достаточной высоте. Длинный текст ограничен строками; отмены по 48dp, semantic palette и единый радиус сохраняются. Это chat-specific адаптация текущих MessageQuote/AttachmentCard, без нового глобального состояния или отдельного UI-kit.

Не весь план завершён. Следующий приоритет: закрыть оставшуюся физическую матрицу (TalkBack, комбинированный preview при увеличенном шрифте, подложка после перезапуска), затем подключить настоящий **текстовый** Direct через подготовленный presenter и существующие команды runtime. Реальные media/reply/edit/delete недоступны в текущем mobile API и требуют отдельного согласованного контракта. Demo-очередь в настоящий чат переносить нельзя.
