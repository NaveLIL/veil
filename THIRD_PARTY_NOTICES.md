# Third-party software / Стороннее ПО

Veil distributions contain third-party software. Those components remain
under their own licenses and copyright notices; the Veil
`AGPL-3.0-or-later` license does not replace them.

Дистрибутивы Veil содержат сторонние компоненты. На них продолжают
распространяться собственные лицензии и уведомления правообладателей; лицензия
Veil `AGPL-3.0-or-later` их не заменяет.

## Distributed notices

Release artifacts contain a generated `THIRD_PARTY_NOTICES.txt`:

- Linux and Windows desktop packages embed the notice as a Tauri resource;
- each desktop platform also publishes its notice as a separate, checksummed
  release asset;
- the gateway container stores the Go dependency notice in
  `/usr/share/licenses/veil/THIRD_PARTY_NOTICES.txt` alongside Veil's own
  `LICENSE`, `NOTICE`, and trademark policy; `ALPINE_PACKAGES.txt` records the
  exact Alpine runtime package inventory and its declared license expressions.

The inventories are generated from the committed `Cargo.lock`,
`veil-desktop/pnpm-lock.yaml`, and `veil-server/go.sum`. The generator copies
license and notice material supplied by upstream packages. Rust SPDX matching
is performed by a pinned `cargo-about` release. A missing or unapproved license
stops generation and therefore stops the release.

Because Go module metadata has no standard SPDX field, the gateway additionally
requires an exact platform-aware module/version match in
`third_party/go-modules.allow`. A dependency update must update that file only
after its upstream license material has been reviewed. npm license expressions
are checked against the explicit approved-license policy in the generator.

## Reproduce locally

Install the locked application dependencies first, then run:

```sh
cargo install cargo-about --version 0.9.1 --locked --features cli
pnpm --dir veil-desktop install --frozen-lockfile
(cd veil-server && go mod download)

node scripts/generate-third-party-notices.mjs \
  --component desktop \
  --output veil-desktop/src-tauri/resources/THIRD_PARTY_NOTICES.txt

node scripts/generate-third-party-notices.mjs \
  --component gateway \
  --output veil-server/THIRD_PARTY_NOTICES.txt
```

Generated `.txt` files are build outputs and are not edited or committed.
When dependency metadata changes, review both the dependency diff and the
generated notice diff before publishing a release.

This inventory is a compliance aid, not a substitute for reviewing the terms
of a dependency before adding or redistributing it.
