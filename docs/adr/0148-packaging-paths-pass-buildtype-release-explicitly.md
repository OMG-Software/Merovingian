# Packaging paths pass `--buildtype=release` explicitly; `default_options` keeps Meson's default

* Status: accepted
* Date: 2026-10-15

Technical Story: OPS-5 in the 29 September 2026 security audit.

## Context and Problem Statement

`meson.build` sets no `buildtype`, so Meson builds `debug` (`-O0`). `meson.build` only
defines `_FORTIFY_SOURCE` when optimising, because glibc ignores it (and warns) at `-O0`.
`src/main.cpp` refuses to start unless every startup hardening check reports `enabled`,
and the `FORTIFY_SOURCE` check cannot be `enabled` without the macro. The Docker image
and the deb, FreeBSD, NetBSD and OpenBSD package scripts passed no buildtype, so every
binary they shipped refused to start.

Either each packaging path asks for a release build, or `meson.build` makes `release` the
default for everyone.

## Considered Options

* Pass `--buildtype=release` in every packaging path (each `scripts/build-*-pkg.sh`,
  `scripts/build-deb.sh`, the `Dockerfile`), pinned by a tooling test.
* Set `buildtype=release` in `meson.build`'s `default_options`.

## Decision Outcome

Chosen option: pass `--buildtype=release` in every packaging path, because the default
applies to every build that does not name a buildtype, and most of those are not
packages.

`python build.py wsl` with no profile, the plain CI test jobs and anyone running
`meson setup build` to work on the code all rely on the `debug` default today. Making
`release` the default would quietly turn them into `-O3` builds with `NDEBUG` defined:
every `assert` in the code and its tests would vanish from the main test run, debugging
would get harder, and compile times would rise, all to fix a problem that exists only in
the half-dozen scripts that produce shipped artifacts.

Rules for future code:

* Any new script or recipe that builds a shipped artifact with a bare `meson setup` passes
  `--buildtype=release` and is added to `PACKAGING_SCRIPTS` in
  `tests/tooling/test_packages_workflow.py`.
* The RPM specs are the exception: the distribution `%meson` macro pins its own buildtype
  and supplies `-O2` and `_FORTIFY_SOURCE` through `%optflags`, which `meson.build`
  accepts because it checks `optimization != '0'`, not the buildtype.
* `meson.build` prints a configure-time warning when hardening is on and
  `optimization=0`, so a source build that will not start says so before it compiles.

### Positive Consequences

* Development and test builds keep `debug`, so assertions stay live in the main suite.
* The release requirement sits next to each packaging command, where a reviewer sees it,
  and a tooling test fails if one goes missing.
* The packages workflow now boots the installed deb and the Docker image through
  `scripts/check-startup-hardening-gate.sh`, so a packaging path that regresses fails CI
  rather than an operator's first start.

### Negative Consequences

* An operator who builds from source with a bare `meson setup` still gets a binary that
  refuses to start. It fails closed and the configure warning says why, and the user
  manual and release process name the flag, but it is one more thing to know.

## Links

* Related to [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md) — the
  startup gate's config sets `federation.worker.allow_without_landlock=true` for the same
  reason the startup integration test does.
