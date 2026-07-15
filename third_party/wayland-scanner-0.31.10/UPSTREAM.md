# Vendored wayland-scanner 0.31.10

This directory contains the published `wayland-scanner` 0.31.10 crate source.
It is temporarily patched to depend on `quick-xml` 0.41 instead of 0.39.

- Upstream repository: <https://github.com/Smithay/wayland-rs>
- Published crate version: `0.31.10`
- Published crate SHA-256: `9c324a910fd86ebdc364a3e61ec1f11737d3b1d6c273c0239ee8ff4bc0d24b4a`
- Upstream source revision recorded by crates.io: `a3d7927d87799b2955bf491b51c7c2a3a82da661`
- Compatibility reference: `ec2d932855593d48aa83c76820f3efbcfea86d39`
- Security-bump reference: `d07c4f91f28b42e5a485823ffd9d8d5a210b1053`
- Addressed advisories: `RUSTSEC-2026-0194`, `RUSTSEC-2026-0195`

The compatibility reference contains the one parser API adjustment required
when leaving quick-xml 0.39. The security-bump reference states that moving
from 0.40 to 0.41 requires no further scanner code changes. Using the released
scanner source avoids unrelated, unreleased generator API changes present on
upstream's main branch. Remove this directory and the root Cargo patch once
crates.io publishes a compatible fixed scanner release.

The upstream source remains licensed under the MIT license in `LICENSE.txt`.
