# Vendored lru 0.16.4

This directory contains the published `lru` 0.16.4 crate source and applies
only the upstream panic-safety fix for `RUSTSEC-2026-0253`.

- Upstream repository: <https://github.com/jeromefroe/lru-rs>
- Published source commit: `d8c7f5ca51a86a8f561c14e21508a0f757aa05ad`
- Upstream fix PR: <https://github.com/jeromefroe/lru-rs/pull/238>
- Upstream fix commit: `2776ded569ee89a99c515bca8194f65639182c96`
- Fixed upstream release: `0.18.2`
- Addressed advisory: `RUSTSEC-2026-0253`
- License: MIT

Tantivy 0.26.1 currently requires the `lru` 0.16 line, so Cargo cannot select
the fixed 0.18.2 release directly. The patch detaches a removed node from the
intrusive list before freeing it and running the key destructor, matching the
upstream fix without changing the released 0.16.4 API.

Remove this vendored crate as soon as the supported Tantivy release accepts
`lru >=0.18.2`. Until then, compare this directory against the crates.io
0.16.4 source plus the single upstream fix before making any further change.

`cargo audit` identifies packages by name and version and cannot recognize a
source-level backport. Security CI therefore tests this crate directly and
suppresses only `RUSTSEC-2026-0253` after the patched source has replaced the
registry package. That suppression must be removed together with this patch.
