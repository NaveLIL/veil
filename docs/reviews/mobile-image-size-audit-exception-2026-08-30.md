# Mobile `image-size` audit exception — 2026-08-30

## Decision

Mobile CI temporarily ignores only these two pnpm advisories:

- `GHSA-w3rx-r6r6-pgpr`
- `GHSA-5p2g-fcmc-qvqq`

The exception expires on **2026-09-30** and must be re-reviewed or removed by
then. It does not permit ignoring another advisory, package, severity, or
dependency path.

## Evidence

Both advisories affect `image-size <=2.0.2` and describe infinite-loop denial of
service in the ICNS, JXL, or HEIF parsers. Veil resolves `image-size 1.2.1`
through React Native 0.79 / Metro 0.82.5. Metro uses it while inspecting project
image assets during the build; the package is not called by Veil's Android
message, identity, transport, or cryptographic runtime.

The advisory database currently claims `>=2.0.3` as patched, but no 2.0.3
package has been published and the upstream `image-size` repository was
archived on 2026-06-03. Expo SDK 56 is also reported to retain this dependency,
so upgrading the whole mobile stack does not yet provide a supported fixed
version.

References:

- <https://github.com/image-size/image-size/releases>
- <https://github.com/github/advisory-database/issues/9028>
- <https://github.com/expo/expo/issues/48670>

## Exposure and controls

- Only repository-controlled image assets reach Metro in trusted branch and
  release builds.
- Production APKs do not accept an image and pass it to this Node package.
- Pull-request CI is disposable and receives no production secrets. A malicious
  asset could at worst consume the bounded hosted runner until GitHub cancels
  the job.
- The exception is expressed as two exact GHSA identifiers in the mobile
  workspace `auditConfig`, consumed by the unchanged CI audit command. All
  other low-or-higher pnpm advisories still fail CI.

## Removal gate

Remove the exception immediately when any of these becomes available:

1. Metro/React Native/Expo removes `image-size` or uses a maintained replacement;
2. a supported upstream release fixes both parser loops;
3. Veil replaces the current Expo/Metro build path with a reviewed supported
   toolchain that does not resolve the vulnerable package.

At each dependency update, run `pnpm audit --json`, confirm both exact paths,
and verify that the exception has not started hiding a runtime-reachable use.
