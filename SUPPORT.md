# Поддержка Veil / Veil Support

Veil — pre-release проект без стабильной версии, внешнего security-аудита,
гарантии обратной совместимости или SLA. Поддержка предоставляется best effort.
Не используйте Preview как единственное средство хранения критичных данных.

## Куда обращаться

| Ситуация | Канал |
|---|---|
| Воспроизводимая ошибка | [GitHub Bug Report](https://github.com/NaveLIL/veil/issues/new?template=bug_report.yml) |
| Предложение или изменение продукта | [GitHub Feature Request](https://github.com/NaveLIL/veil/issues/new?template=feature_request.yml) |
| Установка локального Node | [deploy/README.md](deploy/README.md) и затем Bug Report |
| Вопрос по архитектуре | [docs/README.md](docs/README.md), затем тематический Issue |
| Уязвимость | Только приватно по [SECURITY.md](SECURITY.md) |
| Нарушение правил сообщества | Приватно по [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |

Адрес **security@erez.pro** не предназначен для обычной настройки, feature
requests или восстановления аккаунта.

## Что приложить к обычному Issue

- точную Preview-версию и Git commit;
- ОС, архитектуру и способ установки;
- компонент и минимальные шаги воспроизведения;
- ожидаемое и фактическое поведение;
- очищенный фрагмент логов;
- сведения о собственном Node без паролей, токенов и приватных адресов.

Никогда не прикладывайте recovery phrase, PIN, private keys, access tokens,
message plaintext, production database или полные несаницированные логи.
Скриншоты должны использовать тестовые аккаунты.

## Границы поддержки

Maintainers не могут восстановить E2EE-ключи, recovery phrase, удалённые
сообщения или данные стороннего self-hosted Node. За резервные копии,
сертификаты, DNS, обновления и retention своего Node отвечает его оператор.
Старые Preview и неофициальные сборки не получают обещанных backport-исправлений.

Перед Issue проверьте актуальный master, открытые Issues, документацию и
целостность официального artifact по SHA256SUMS.

## English summary

Veil is unaudited pre-release software with best-effort support and no SLA.
Use the Bug Report or Feature Request forms for public, non-sensitive topics.
Read [deploy/README.md](deploy/README.md) for self-hosting. Report
vulnerabilities privately according to [SECURITY.md](SECURITY.md).

Include the exact Preview version/commit, platform, installation method,
minimal reproduction, and sanitized logs. Never post recovery phrases,
private keys, tokens, message plaintext, production data, or unsanitized
logs. Maintainers cannot recover E2EE secrets or data from third-party Nodes.
