Veil desktop release resources
==============================

Official packages generate THIRD_PARTY_NOTICES.txt in this directory from the
locked Cargo and pnpm dependencies before Tauri bundles the application.

This bootstrap file keeps direct Cargo checks deterministic. It is not a
substitute for the generated third-party notice in a distributable build.

See ../../../THIRD_PARTY_NOTICES.md in the source repository for the generation
and compliance process.
