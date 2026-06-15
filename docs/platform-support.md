# Platform support tiers

Merovingian targets POSIX server platforms. Support is organised into tiers by
how much continuous-integration coverage a platform receives. A platform's tier
states what is *guaranteed by CI*, not whether it happens to work elsewhere.

## Build toolchain and minimum platform versions

Merovingian is C++26 (`cpp_std=c++26` in `meson.build`). That is the hard
constraint on which platform versions can build it: the C++26 compiler **and** a
matching C++ standard library only ship in recent OS releases. Older releases
cannot build from source — use the portable static tarball (see Tier 2) instead.

**Toolchain floor (all platforms):**

- **Clang ≥ 18** (`-std=c++26`) or **GCC ≥ 14**, with the matching
  `libc++` / `libstdc++` C++26 runtime.
- **Meson ≥ 1.1.0** and Ninja.
- Core dependencies are vendored and built from subprojects
  (`--wrap-mode=forcefallback`); only the base toolchain and the optional image
  codecs (`libpng`, `libjpeg-turbo`) come from the OS.

**Minimum OS versions that ship a C++26 toolchain:**

| Platform | Minimum version | Toolchain source | CI image |
|---|---|---|---|
| Ubuntu / Debian | Ubuntu 24.04 LTS · Debian 13 (trixie) | distro clang 18+ | `ubuntu-latest` (24.04) |
| Fedora / RHEL family | Fedora 40+ (RHEL 10, or clang module on 9) | dnf clang 18+ | `fedora:latest` |
| FreeBSD | 14.1+ (base clang ≥ 18) | base clang | `vmactions/freebsd-vm@v1` (14.x) |
| OpenBSD | 7.6+ with the `llvm` package (clang ≥ 18) | `llvm` package, not base | `vmactions/openbsd-vm@v1` (7.x) |
| NetBSD | 10+ with pkgsrc `clang` (≥ 18) | pkgsrc clang | `vmactions/netbsd-vm@v1` (10.x) |

The CI VM/runner images track the current stable release of each platform, so
"build on" is the latest stable and "build for" is the minimum version in the
table above. Earlier releases (e.g. Ubuntu 22.04, Debian 12, FreeBSD 13,
OpenBSD ≤ 7.5) ship a pre-C++26 toolchain and are **not** buildable from source.

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
| OpenBSD `.tgz` (standalone `pkg_create`) | `packages.yml` | Tier 1 OpenBSD |
| NetBSD `.tgz` (standalone `pkg_create`) | `packages.yml` | Tier 1 NetBSD |
| Portable static Linux tarball (musl) | `packages.yml` | Tier 1 Linux (the sandboxed thumbnail worker is omitted when static image codecs are unavailable; thumbnails then fall back to original bytes) |

The OpenBSD and NetBSD package jobs build with standalone `pkg_create(1)` (no
ports/pkgsrc tree), generating a framework-free packing list from the staged
install. The checked-in `packaging/openbsd/PLIST` and `packaging/netbsd/Makefile`
remain the ports/pkgsrc recipes for downstream porters and are kept in sync by
version-consistency tests.

### Older Linux distributions — the static tarball

Distributions older than the minimums above (e.g. Ubuntu 22.04, Debian 12,
RHEL 9, or any host whose glibc / toolchain predates C++26) cannot build from
source and cannot run a glibc-dynamic build linked against newer libraries. For
those hosts the **portable static Linux tarball** is the supported path: it is
built against musl and **statically links essentially every dependency**
(OpenSSL, libpq, SQLite, libcurl, libsodium, zlib, and the C/C++ runtime), so it
runs on old and minimal systems with no shared-library or glibc version
requirements.

The trade-off is size: because it links the world, the static binary is **much
larger** than the dynamically linked distro packages, carries no automatic
security updates for its bundled libraries (the tarball must be rebuilt and
redeployed to pick up dependency fixes), and omits the sandboxed thumbnail worker
when static image codecs are unavailable (thumbnails then fall back to original
bytes). Prefer a native Tier 1/Tier 2 package whenever the platform is new
enough; use the static tarball only when it is not.

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
