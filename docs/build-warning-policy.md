# Build and warning policy

This capability note describes the runtime-wired build policy surface used by
local development, WSL, BSD, and CI jobs.

## Included now

- Meson C++26 configuration with `werror=true`.
- Project-owned warning flag set in `meson.build`.
- Compiler/linker hardening option enabled by default where supported.
- Reusable Linux and BSD build wrappers.
- Windows-to-WSL launchers (`build-wsl.cmd` and `scripts/build-wsl.ps1`) that
  delegate to `scripts/build-wsl.sh` through the default or explicitly
  selected WSL distro.
- Named wrapper profiles:
  - `debug`
  - `release`
  - `sanitizer`
  - `coverage`
  - `fuzz`
  - `hardened`
- CI jobs call the reusable wrappers so local developers can reproduce the same
  build entrypoints.
- Release artifacts carry detached GPG signatures, SLSA provenance attestations,
  SHA-256 checksums, SPDX/CycloneDX SBOMs, and a machine-readable license
  summary.
- The static Linux fallback tarball is verified for byte-for-byte reproducibility
  by `scripts/reproducible-build.sh` and a dedicated CI job.

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

## Included now (continued)

- **Mandatory fuzz execution on every push and pull request** — this was
  already true when this document's "Deliberately not included" list below
  claimed otherwise (audited 0.12.1, corrected here). `.github/workflows/fuzz.yml`
  triggers on `push`/`pull_request` (not just the weekly schedule), and
  `scripts/run-fuzz-targets.sh` runs each of the seven fuzz targets under
  `set -eu` with `-error_exitcode=77`, so any crash, leak, or UBSan finding
  fails the job — there is no `continue-on-error`.
- **Build-time link-time hardening enforcement** (0.12.1) —
  `scripts/check-elf-hardening.sh` statically inspects a built binary's ELF
  headers (PIE, `PT_GNU_RELRO`, `DT_BIND_NOW`, non-executable
  `PT_GNU_STACK`) and fails closed if any is missing. Unlike the runtime
  hardening self-check (which needs a live process satisfying both a
  hardened build *and* `CAP_SETPCAP`, a combination most CI jobs cannot
  provide — see `docs/hardening.md`), this needs only the built binary, so
  it runs identically whether the CI job is root, non-root, or
  containerized. Wired into the `ubuntu-hardened-listener-coverage` CI job
  against every shipped binary, and per-platform in
  `.github/workflows/release.yml` via `scripts/collect-release-evidence.sh`.

## Deliberately not included

- Platform-specific production hardening enforcement beyond current compiler
  and linker flags **and** the ELF-header build gate above — specifically,
  the *runtime* hardening self-check (seccomp, capability bounding,
  pledge/unveil, Capsicum) is still not exercised by most CI jobs (see
  `docs/hardening.md`'s CI-gates section for exactly which job now does).
- Byte-for-byte reproducibility for distro packages (`.deb`, `.rpm`, BSD
  packages) — reproducible build verification currently covers only the
  static Linux fallback tarball.
