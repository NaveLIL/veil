# Release downloads

Этот каталог — только локальная точка монтирования для разработки. Релизные
бинарники, `SHA256SUMS` и `latest.json` генерируются GitHub Actions и **не
коммитятся в Git**.

Лендинг показывает карточку загрузки только тогда, когда доступен
`/downloads/latest.json`. Манифест имеет следующий формат:

```json
{
  "version": "0.1.0",
  "published_at": "2026-07-14T12:00:00Z",
  "commit": "0123456789abcdef0123456789abcdef01234567",
  "files": [
    {
      "platform": "linux",
      "kind": "deb",
      "label": "Linux Debian/Ubuntu (x86_64)",
      "filename": "Veil-linux-amd64.deb",
      "size": 12345678,
      "sha256": "..."
    }
  ]
}
```

Для локальной проверки можно положить сюда `latest.json`, `SHA256SUMS` и
указанные в манифесте файлы, затем запустить gateway с
`VEIL_DOWNLOADS_DIR=cmd/gateway/downloads`.

В production файлы находятся вне image и репозитория. Release workflow сначала
загружает их в draft GitHub Release, затем через обязательные VPS secrets — в
новый versioned каталог и атомарно переключает `/srv/veil/releases/current`.
Только после успешной синхронизации GitHub Release становится публичным.
Системный Nginx раздаёт этот каталог напрямую; Go gateway не расходует память и
соединения на большие AppImage/installer файлы.
