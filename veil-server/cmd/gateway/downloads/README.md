# Release artifacts

Эту папку gateway раздаёт по пути `/downloads/<file>`. Бинарники в git **не
коммитятся** (см. `.gitignore`) — они слишком большие. Чтобы развернуть с
рабочими ссылками на скачивание, надо положить сюда собранные артефакты
вручную.

## Сборка

### Linux (.deb + .AppImage)

```sh
cd veil-desktop
NO_STRIP=true pnpm tauri build --bundles deb,appimage
cp ../target/release/bundle/deb/Veil_*.deb       ../veil-server/cmd/gateway/downloads/
cp ../target/release/bundle/appimage/Veil_*.AppImage ../veil-server/cmd/gateway/downloads/
cd ../veil-server/cmd/gateway/downloads
sha256sum Veil_*.deb Veil_*.AppImage > SHA256SUMS
```

`NO_STRIP=true` обязателен на дистрибутивах с современным glibc — старый
`strip` из `linuxdeploy` не понимает `.relr.dyn` (DT_RELR) секции.

### macOS / Windows / Android

Появятся, когда дойдут руки до CI с раннерами для каждой платформы.

## Альтернатива: внешний volume

Если бинарники должны жить вне образа, поднимите gateway с переменной:

```sh
VEIL_DOWNLOADS_DIR=/srv/veil-downloads ./veil-gateway
```
