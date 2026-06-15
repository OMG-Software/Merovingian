# Platform support tiers

Merovingian targets POSIX server platforms. Support is organised into tiers by
how much continuous-integration coverage a platform receives. A platform's tier
states what is *guaranteed by CI*, not whether it happens to work elsewhere.

## Tier 1 — Supported (CI-gated per pull request)

Tier 1 platforms build **and run the full test suite** (unit, integration,
conformance, smoke) on every pull request. Platform-specific runtime behaviour —
the startup hardening self-check, runtime-hardening integration tests, and the
server config/version smoke tests — is exercised on the platform itself, not
just cross-compiled. A regression on a Tier 1 platform blocks merge.

| Platform | CI job | Toolchain | Notes |
|---|---|---|---|
| Linux (glibc, Ubuntu) | `linux-build-and-test` | clang | Reference platform |
| Linux (Red Hat family, Fedora) | `fedora-build-and-test` | clang, container | dnf-supplied libraries |
| FreeBSD | `freebsd` | clang (base) | `vmactions/freebsd-vm` |
| OpenBSD | `openbsd` | clang (`llvm` package) | `vmactions/openbsd-vm` |
| NetBSD | `netbsd` | clang (pkgsrc) | `vmactions/netbsd-vm` |

All Tier 1 jobs build through the shared wrappers (`scripts/build-linux.sh`,
`scripts/build-bsd.sh`) with `--wrap-mode=forcefallback`, so the core
dependencies are built from vendored subprojects and only the platform's image
codecs (`libpng`, `libjpeg-turbo`) and base toolchain come from the OS.

## Tier 2 — Packaged (CI-built artifacts)

Tier 2 produces installable artifacts in CI. Build and packaging are gated;
runtime behaviour is covered transitively by the matching Tier 1 platform.

| Artifact | Workflow | Runtime coverage via |
|---|---|---|
| Debian/Ubuntu `.deb` | `packages.yml` | Tier 1 Linux |
| Fedora/RHEL `.rpm` | `packages.yml` | Tier 1 Fedora |
| FreeBSD `.pkg` | `packages.yml` | Tier 1 FreeBSD |
| OpenBSD package metadata | `release.yml` | Tier 1 OpenBSD |
| NetBSD / pkgsrc metadata | `release.yml` | Tier 1 NetBSD |
| Portable static Linux tarball (musl) | `packages.yml` | Tier 1 Linux (the sandboxed thumbnail worker is omitted when static image codecs are unavailable; thumbnails then fall back to original bytes) |

## Tier 3 — Best-effort (not in CI)

Expected to work but not continuously verified. Issues are accepted but not
release-blocking.

- **HardenedBSD** — uses the FreeBSD `pkg` toolchain and `scripts/build-bsd.sh`.
- **Other Linux distributions** — via the portable static tarball or a from-source build.
- **Windows** — development only, through WSL (`python build.py wsl`). Not a server deployment target.
- **macOS** — not a supported target.

## Per-platform hardening posture

Runtime hardening is platform-specific and reported by the startup self-check
(see [hardening-alpha-exceptions.md](hardening-alpha-exceptions.md)).

| Control | Linux | FreeBSD | OpenBSD | NetBSD |
|---|---|---|---|---|
| seccomp-bpf syscall filter | enabled | n/a | n/a | n/a |
| ELF RELRO / BIND_NOW / noexec stack probe | enabled | enabled | enabled | enabled |
| pledge / unveil | n/a | n/a | alpha exception (scaffolded) | n/a |
| Capsicum | n/a | alpha exception (scaffolded) | n/a | n/a |
| Resource limits, no-new-privs, core-dump policy | enabled / alpha exception | partial | partial | partial |

The sandboxed thumbnail worker applies its own `setrlimit` clamps and (on Linux)
the seccomp filter regardless of platform; where those facilities are
unavailable it still runs with the resource limits that the OS supports.

## Changing a platform's tier

Promoting a platform to Tier 1 requires a green build-and-test CI job on that
platform. Demoting requires removing the job and recording the reason in
`CHANGELOG.md`. Keep this document and the `Platform support` row in
[todos/capability-gaps.md](todos/capability-gaps.md) in sync with the actual CI
job set.
