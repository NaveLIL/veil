# Vendored openmls_rust_crypto 0.4.4

This directory contains the published `openmls_rust_crypto` 0.4.4 crate
source. It is temporarily patched to depend on the 0.7 line of `hpke-rs`,
`hpke-rs-crypto`, and `hpke-rs-rust-crypto` instead of the 0.6 line.

- Upstream repository: <https://github.com/openmls/openmls>
- Published crate version: `0.4.4`
- Published crate SHA-256: `e864b90d4b297b84a46ada993142a72392737248050100533ae063586c7f433f`
- Upstream source revision recorded by crates.io: `8ebb8f406c8f3ec90d04eadb18010b5c57ad8d92`
- Security-bump reference: <https://github.com/openmls/openmls/pull/2117>
- Security-bump merge revision: `0e99bc8814d136f0bc7bc9ce86dd288eb32273ed`
- Addressed advisories: `RUSTSEC-2026-0207`, `RUSTSEC-2026-0208`,
  `RUSTSEC-2026-0209`, `RUSTSEC-2026-0211`, `RUSTSEC-2026-0212`

Upstream pull request 2117 made the same three dependency updates without
changing `openmls_rust_crypto` source code. The vendored `src` directory is
byte-for-byte identical to the published 0.4.4 crate. Keeping OpenMLS itself,
its traits, and its memory storage on the existing 0.7/0.4 release lines avoids
an unrelated wire or storage-format migration.

Remove this directory and the root Cargo patch once crates.io publishes a
compatible `openmls_rust_crypto` release that depends on hpke-rs 0.7 or later.

The upstream source remains licensed under the MIT license in `LICENSE.txt`.
