# Build and warning policy

This capability note describes the runtime-wired build policy surface used by
local development, WSL, BSD, and CI jobs.

## Included now

- Meson C++26 configuration with `werror=true`.
- Project-owned warning flag set in `meson.build`.
- Compiler/linker hardening option enabled by default where supported.
- Reusable Linux and BSD build wrappers.
- Windows-to-WSL launchers (`wsl-build.cmd`, the compatibility alias
  `build-wsl.cmd`, and `scripts/build-wsl.ps1`) that delegate to
  `scripts/build-wsl.sh` through the default or explicitly selected WSL
  distro.
- Named wrapper profiles:
  - `debug`
  - `release`
  - `sanitizer`
  - `coverage`
  - `fuzz`
  - `hardened`
- CI jobs call the reusable wrappers so local developers can reproduce the same
  build entrypoints.

## Security posture

The wrappers keep compiler, warning, sanitizer, fuzz, coverage, and hardening
choices explicit at the project boundary. Profiles are names for reviewed Meson
option sets; they do not weaken warning-as-error policy or bypass dependency
checks.

Fallback builds use Meson's default `wrappedruntime` test setup to expose
staged curl external-project library directories through `LD_LIBRARY_PATH`.
This keeps Fedora and BSD test execution aligned with the wrap-built runtime
library that can still be loaded from the current Meson tree.

The aggregate Catch2 unit-test binary has an explicit 120 second Meson timeout.
That test executable now covers enough runtime behavior that fallback,
coverage, and sanitizer jobs can exceed Meson's 30 second default even when all
assertions pass.

Post-build validation scripts that execute `merovingian-server` directly must
also expose staged curl runtime libraries from the selected build directory.
OpenSSL, LibSodium, and PostgreSQL libpq are resolved from OS packages and do
not require build-local runtime library paths.

`_FORTIFY_SOURCE=3` is requested only when Meson reports an optimized build.
That keeps the default debug profile warning-clean on glibc platforms, where
FORTIFY without optimization is itself a compiler warning and this project
treats warnings as errors.

## Deliberately not included

- Reproducible release artifact generation.
- Signed release archives and provenance.
- Mandatory fuzz execution in every CI run.
- Platform-specific production hardening enforcement beyond current compiler and
  linker flags.
