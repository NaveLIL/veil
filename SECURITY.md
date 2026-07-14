# Security Policy / Политика безопасности

Veil находится в стадии **pre-release**. Проект ещё не проходил независимый
криптографический или комплексный security-аудит. Открытый исходный код,
внутренние review-документы и автоматические тесты не являются заменой
внешнего аудита или гарантией безопасности.

Veil is **pre-release** software. It has not completed an independent
cryptographic or comprehensive security audit. Public source code, internal
review notes, and automated tests are not a substitute for an external audit
or a security guarantee.

## Русский

### Поддерживаемые версии

| Поверхность | Security-поддержка |
|---|---|
| Текущая ветка **master** | Исправления принимаются на основе риска, без SLA |
| Последний опубликованный Preview, если он есть | Best effort; может потребоваться обновление до новой Preview-сборки |
| Старые Preview и неофициальные/ручные сборки | Не поддерживаются |
| Изменённые форки и сторонние Veil Node | Отвечает оператор; общие upstream-уязвимости можно сообщать нам |

У Veil пока нет стабильной поддерживаемой версии. Исправления обычно сначала
попадают в master. Backport для старых Preview не обещается.

### Как сообщить об уязвимости

Не создавайте публичный Issue, Discussion или Pull Request с деталями
неисправленной уязвимости. Предпочтительный канал —
[приватный GitHub security advisory](https://github.com/NaveLIL/veil/security/advisories/new).
Если GitHub недоступен, отправьте приватное сообщение на
**security@erez.pro** с темой **[Veil Security]**. Актуальные машиночитаемые
контакты опубликованы в
[security.txt](https://veil.erez.pro/.well-known/security.txt).

Почта не заявлена как канал со сквозным шифрованием. **Не отправляйте
чувствительные данные**, включая:

- recovery phrase, PIN, приватные ключи, токены, cookie и пароли;
- plaintext сообщений, реальные контактные данные и содержимое аккаунтов;
- production-базы, дампы памяти и полные несаницированные логи;
- рабочий exploit против чужого аккаунта или публичного Veil Node.

Используйте тестовый Node, синтетические аккаунты и минимальный PoC. Сначала
опишите находку текстом; если нужен более защищённый способ передачи
материалов, запросите его до отправки вложений.

Полезно указать:

- компонент, платформу, версию Preview и точный Git commit;
- предполагаемое влияние и модель атакующего;
- минимальные воспроизводимые шаги или безопасный PoC;
- ожидаемое и фактическое поведение;
- очищенные логи, stack trace и возможное исправление, если оно известно.

### Безопасное исследование

Проверяйте только собственные аккаунты, устройства и инфраструктуру либо
системы, на тестирование которых у вас есть явное разрешение. Не нарушайте
приватность, не закрепляйтесь в системе, не изменяйте чужие данные и не
ухудшайте доступность сервиса. Социальная инженерия, фишинг, DDoS и массовое
сканирование не являются допустимым способом проверки.

Обычные ошибки доступности тестового сервиса, спам, feature requests и
проблемы локальной установки без security-влияния следует направлять через
обычные Issue-шаблоны.

### Координация раскрытия

Мы постараемся подтвердить получение, оценить влияние и согласовать дальнейшие
шаги, но Preview-проект не предоставляет SLA и не обещает вознаграждение.
Пожалуйста, дайте проекту разумный срок — ориентир до **90 дней** — до
публичного раскрытия. При активной эксплуатации или высоком риске сроки могут
быть согласованы отдельно.

## English

### Supported versions

| Surface | Security support |
|---|---|
| Current **master** branch | Risk-based fixes on a best-effort basis, without an SLA |
| Latest published Preview, if one exists | Best effort; upgrading to a newer Preview may be required |
| Old Previews and unofficial/manual builds | Unsupported |
| Modified forks and third-party Veil Nodes | Operator responsibility; shared upstream flaws are welcome |

Veil does not yet have a stable supported release. Fixes normally land on
master first, and backports to older Preview builds are not promised.

### Reporting a vulnerability

Do not open a public Issue, Discussion, or Pull Request containing details of
an unpatched vulnerability. Prefer a
[private GitHub security advisory](https://github.com/NaveLIL/veil/security/advisories/new).
If GitHub is unavailable, email **security@erez.pro** with the subject
**[Veil Security]**. The current machine-readable contacts are published in
[security.txt](https://veil.erez.pro/.well-known/security.txt).

Email is not represented as an end-to-end encrypted reporting channel. **Do
not send sensitive data**, including:

- recovery phrases, PINs, private keys, tokens, cookies, or passwords;
- message plaintext, real contact details, or real account content;
- production databases, memory dumps, or full unsanitized logs;
- a working exploit against another person or a public Veil Node.

Use a test Node, synthetic accounts, and the smallest safe proof of concept.
Describe the finding in text first. If sensitive supporting material is truly
necessary, ask for an appropriate transfer method before sending attachments.

Please include:

- affected component, platform, Preview version, and exact Git commit;
- expected impact and attacker model;
- minimal reproduction steps or a safe proof of concept;
- expected and actual behavior;
- sanitized logs, stack traces, and a suggested mitigation if known.

### Research boundaries

Test only accounts, devices, and infrastructure you own or are explicitly
authorized to assess. Do not invade privacy, establish persistence, modify
other users' data, or degrade service availability. Social engineering,
phishing, denial of service, and broad automated scanning are not acceptable
testing methods.

Routine Preview outages, spam, feature requests, and local setup problems
without security impact belong in the regular Issue templates.

### Coordinated disclosure

We will make a best-effort attempt to acknowledge the report, assess impact,
and coordinate next steps, but this Preview project offers no response SLA or
guaranteed reward. Please allow a reasonable remediation window, normally up
to **90 days**, before public disclosure. Active exploitation or unusually
high risk may require a separately coordinated timeline.
