# Build and warning policy

This capability note describes the runtime-wired build policy surface used by
local development, WSL, BSD, and CI jobs.

## Included now

- Meson C++26 configuration with `werror=true`.
- Project-owned warning flag set in `meson.build`.
- Compiler/linker hardening option enabled by default where supported.
- Reusable Linux and BSD build wrappers.
- Windows-to-WSL wrapper for Ubuntu-24.04 local builds.
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
staged external-project library directories through `LD_LIBRARY_PATH`. This
keeps Fedora and BSD test execution aligned with the libraries that were built
for the current Meson tree.

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
