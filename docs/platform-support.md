# Platform support tiers

Merovingian targets POSIX server platforms. Support is organised into tiers by
how much continuous-integration coverage a platform receives. A platform's tier
states what is *guaranteed by CI*, not whether it happens to work elsewhere.

## Build toolchain and minimum platform versions

Merovingian is C++26 (`cpp_std=c++26` in `meson.build`). Two *independent*
constraints decide which platform versions work, and on Linux they are not the
same thing:

1. **Compiler + C++ standard library** — building needs a C++26 toolchain.
2. **System C library (glibc) version** — on Linux the produced binary links
   against the build host's glibc, which decides where it can *run*.

**Toolchain floor (all platforms):**

- **Clang ≥ 18** (`-std=c++26`) or **GCC ≥ 14**, with the matching
  `libc++` / `libstdc++` C++26 runtime. CI (`ci.yml`, `packages.yml`) builds with clang everywhere. The separate
  `coverage.yml` and `sonarcloud.yml` workflows build with GCC 14 (ADR-0217).
- **Meson ≥ 1.1.0** and Ninja.
- Core dependencies are vendored and built from subprojects
  (`--wrap-mode=forcefallback`); only the base toolchain and the optional image
  codecs (`libpng`, `libjpeg-turbo`) come from the OS.

### The glibc constraint (Linux)

On Linux the compiler is necessary but **not sufficient**. glibc is *backward*-
but **not forward-compatible**: a binary linked against glibc 2.39 (Ubuntu 24.04)
requires glibc ≥ 2.39 at runtime and will fail to start on an older system with
a diagnostic like `version 'GLIBC_2.39' not found`. Critically:

- **Installing a newer Clang on an old distro does not help.** The compiler is
  separate from the C library. An old release (e.g. Ubuntu 22.04 / glibc 2.35,
  Debian 12 / glibc 2.36, RHEL 9 / glibc 2.34) ships an old glibc that the C++26
  build links against, and **glibc is not safely upgradable in place** — it is
  the foundation the whole userland is built on.
- Therefore a distro package built on the CI image targets *that image's glibc
  and newer only*. There is no single glibc-dynamic build that runs on both new
  and old Linux.

The escape hatch for old or minimal Linux is the **static musl tarball**
(Tier 2), which has no glibc dependency at all — see below.

**Minimum OS versions (compiler available *and* glibc new enough):**

| Platform | Minimum version | glibc (Linux) | Toolchain source | CI image |
|---|---|---|---|---|
| Ubuntu | Ubuntu 24.04 LTS (packaged; built and tested on 26.04 and 26.10) | ≥ 2.39 | distro clang 18+ | `ubuntu-26.04` runner, `ubuntu:26.10`; `ubuntu:24.04` for its package only |
| Debian | Debian 13 (trixie); Debian 12 is not packaged, use the static tarball | ≥ 2.39 | distro clang 18+ | `debian:trixie` |
| Fedora | Fedora 40+ (source build); Fedora 44 or 45 for the RPM | ≥ 2.39 | dnf clang 18+ | `fedora:44`, `fedora:45` |
| RHEL-compatible | RHEL 10 / AlmaLinux 10 | ≥ 2.39 | dnf clang 18+ (AppStream) | `almalinux:10` |
| OpenSUSE | Tumbleweed (rolling) or Leap 16.0 | current (Tumbleweed); the release's own (Leap) | zypper clang 18+ | `opensuse/tumbleweed`, `opensuse/leap:16.0` |
| FreeBSD | 14.1+ (base clang ≥ 18) for a source build; 15 for the package | n/a (no glibc) | base clang | `vmactions/freebsd-vm` (`release: '15'`, the newest 15.x) |
| OpenBSD | 7.6+ with the `llvm` package (clang ≥ 18) | n/a | `llvm` package, not base | `vmactions/openbsd-vm` (its default 7.x) |
| NetBSD | 10+ with pkgsrc `clang` (≥ 18) | n/a | pkgsrc clang | `vmactions/netbsd-vm` (its default 10.x) |

Every Linux image and the FreeBSD VM are pinned by release, never a moving tag such as
`ubuntu:rolling` or `fedora:latest`, so the release CI tests is the release a package is
built for; a new release is added by editing the workflows
([ADR-0742](adr/0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md)). The OpenBSD and NetBSD VMs run each action's default release.
"Build for" is the minimum version above.
Earlier Linux releases (Ubuntu 22.04, Debian 12, RHEL 9) fail on **both** counts
— pre-C++26 toolchain and too-old glibc — and even after installing a newer
Clang the glibc remains too old, so they are not buildable or runnable from a
glibc-dynamic build. Use the static tarball there. (On the BSDs there is no
glibc; the only floor is a base/packaged clang ≥ 18.)

## System library dependencies

These libraries are **provided by the operating system** on every platform (the
meson dependencies use `allow_fallback: false`), so deployments get distro
security updates and the OS packages declare them as runtime dependencies that
the package manager installs automatically. SQLite, yyjson, and Catch2 are the
only direct dependencies built from vendored subprojects when absent.

| Library | Debian/Ubuntu (`apt`) | Fedora/RHEL (`dnf`) | OpenSUSE (`zypper`) | FreeBSD (`pkg`) | OpenBSD (`pkg_add`) | NetBSD (`pkgin`) |
|---|---|---|---|---|---|---|
| libsodium | `libsodium-dev` | `libsodium-devel` | `libsodium-devel` | `libsodium` | `libsodium` | `libsodium` |
| OpenSSL | `libssl-dev` | `openssl-devel` | `libopenssl-devel` | `openssl` | `openssl` (LibreSSL base) | base system (not pkgsrc `openssl`: pkgsrc's `curl` and `postgresql17-client` link the base OpenSSL, and a second one breaks the link) |
| PostgreSQL libpq | `libpq-dev` | `libpq-devel` | `postgresql-devel` | `postgresql17-client` | `postgresql-client` | `postgresql17-client` |
| libcurl | `libcurl4-openssl-dev` | `libcurl-devel` | `libcurl-devel` | `curl` | `curl` | `curl` |
| libpng | `libpng-dev` | `libpng-devel` | `libpng16-devel` | `png` | `png` | `png` |
| libjpeg-turbo | `libturbojpeg0-dev` | `turbojpeg-devel` | `libjpeg8-devel` | `libjpeg-turbo` | `jpeg-turbo` | `libjpeg-turbo` |

Email pushers (`server.email.smtp_url`) need a libcurl with SMTP. On RHEL-compatible hosts the
default `libcurl-minimal` has none; install the full `libcurl` (`dnf swap libcurl-minimal
libcurl`) to use email, or the server refuses to start with a relay configured. Without SMTP the
email integration scenarios that need an SMTP session are skipped, as on the
`rhel-build-and-test` job.

Runtime package dependencies are declared in the OS packaging metadata
(the `.deb` `Depends`, which `scripts/build-deb.sh` derives with `dpkg-shlibdeps` from the libraries the binaries
link on the release being packaged, because Ubuntu and Debian releases name those packages differently; the rpm spec, `packaging/freebsd/+MANIFEST`
`deps`, `packaging/openbsd/PLIST` `@depend`, `packaging/netbsd/Makefile`
`DEPENDS`), so installing a Merovingian package pulls these libraries in
automatically. `scripts/setup-dev-env.sh` installs the development files for
local builds. The static (musl) tarball links the static variants of these
libraries and therefore has no runtime package dependencies.

## Tier 1 — Supported (CI-gated per pull request)

Tier 1 platforms build **and run the full test suite** (unit, integration,
conformance, smoke) on every pull request. Platform-specific runtime behaviour —
the startup hardening self-check, runtime-hardening integration tests, and the
server config/version smoke tests — is exercised on the platform itself, not
just cross-compiled. A regression on a Tier 1 platform blocks merge.

No BSD job (the three `*-build-and-test` jobs and the FreeBSD, OpenBSD and NetBSD package jobs) may
carry a job-level `continue-on-error`; a failure there fails the run
([ADR-0502](adr/0502-every-bsd-job-is-required-and-the-netbsd-retry-cannot-rescue-it.md)).

| Platform | CI job | Toolchain | Notes |
|---|---|---|---|
| Linux (glibc, Ubuntu 26.04 LTS) | `ubuntu-build-and-test` | clang | Reference platform; GitHub's `ubuntu-26.04` runner image, named by release, never `ubuntu-latest` ([ADR-0650](adr/0650-each-ubuntu-and-opensuse-release-gets-its-own-build-check-and-package.md)). Ubuntu 24.04 is packaged but not built and tested ([ADR-0742](adr/0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md)) |
| Linux (Ubuntu 26.10) | `ubuntu-interim-build-and-test` (check `ubuntu-26.10-build-and-test`) | clang, container | apt-supplied libraries; `ubuntu:26.10`, pinned by release, since GitHub has runner images for LTS releases only |
| Linux (Debian trixie) | `debian-build-and-test` | clang, container | apt-supplied libraries; `debian:trixie` |
| Linux (Red Hat family, Fedora) | `fedora-build-and-test`, which requires `fedora-suite` to pass on each image | clang, container | dnf-supplied libraries; `fedora:44` and `fedora:45` |
| Linux (RHEL-compatible, AlmaLinux 10) | `rhel-build-and-test` | clang, container | dnf+EPEL 10-supplied libraries; `almalinux:10` |
| Linux (OpenSUSE Tumbleweed and Leap 16.0) | `opensuse-build-and-test` (Tumbleweed), `opensuse-leap-build-and-test` | clang, container | zypper-supplied libraries; `opensuse/tumbleweed`, `opensuse/leap:16.0` |
| FreeBSD 15 | `freebsd-build-and-test` | clang (base) | `vmactions/freebsd-vm`, `release: '15'` |
| OpenBSD | `openbsd-build-and-test` | clang (`llvm` package) | `vmactions/openbsd-vm` |
| NetBSD | `netbsd-build-and-test` | clang (pkgsrc) | `vmactions/netbsd-vm` |

`ci.yml` also runs `ubuntu-hardened-listener-coverage` on the Ubuntu runner. It is not a platform row:
it runs the real binary-startup hardening scenario with the file capability the self-check needs.
The scenario still warns and returns success when the hardening self-check refuses startup (and when
the server binary or worker is not set, or it runs as root), so a green job does not by itself prove
the listener ran; check the job log for a "skipped" warning.

All Tier 1 jobs build through the shared wrappers (`scripts/build-linux.sh`,
`scripts/build-bsd.sh`) with `--wrap-mode=forcefallback`, so the core
dependencies are built from vendored subprojects and only the platform's image
codecs (`libpng`, `libjpeg-turbo`) and base toolchain come from the OS.

## Tier 2 — Packaged (CI-built artifacts)

Tier 2 produces installable artifacts in CI. Build and packaging are gated;
runtime behaviour is covered transitively by the matching Tier 1 platform.

| Artifact | Workflow | Runtime coverage via |
|---|---|---|
| Ubuntu `.deb`, one each for 24.04 LTS, 26.04 LTS and 26.10, named `-ubuntu<release>.deb` ([ADR-0650](adr/0650-each-ubuntu-and-opensuse-release-gets-its-own-build-check-and-package.md)) | `packages.yml` (`deb`; the required check "Debian package" is `deb-all-releases`, which passes only when every release built) | Tier 1 Ubuntu |
| Debian 13 (trixie) `.deb`, named `-debian13.deb` | `packages.yml` (`debian-pkg`) | Tier 1 Debian |
| Fedora `.rpm`, one each for Fedora 44 and 45 (`.fc44`, `.fc45`; [ADR-0376](adr/0376-build-an-rpm-for-fedora-44-and-for-fedora-latest.md), [ADR-0742](adr/0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md)) | `packages.yml` (`rpm`) | Tier 1 Fedora |
| RHEL-compatible `.rpm` (AlmaLinux 10, `.el10`) | `packages.yml` (`rhel-rpm`) | Tier 1 RHEL-compatible |
| OpenSUSE `.rpm`, one each for Tumbleweed (`.tumbleweed`) and Leap 16.0 (`.leap16`) | `packages.yml` (`opensuse-rpm`) | Tier 1 OpenSUSE |
| FreeBSD 15 `.pkg`, named `-freebsd15.pkg` | `packages.yml` (`freebsd-pkg`) | Tier 1 FreeBSD |
| OpenBSD `.tgz` (standalone `pkg_create`), named `-openbsd<release>.tgz` | `packages.yml` (`openbsd-pkg`) | Tier 1 OpenBSD |
| NetBSD `.tgz` (tar-assembled, no `pkg_create`), named `-netbsd<release>.tgz` | `packages.yml` (`netbsd-pkg`) | Tier 1 NetBSD |
| Portable static Linux tarball (musl), named `-linux-static-x86_64.tar.gz` | `packages.yml` (`static-linux-fallback`) | Tier 1 Linux (the sandboxed thumbnail worker is omitted when static image codecs are unavailable; thumbnail requests are then answered `404`) |

A package installs only on the distribution release it was built on, because it links against
that release's libraries, so each supported release has its own, and its file name says which.
Every package is x86_64 and built with the hardened profile. A tagged release ships exactly the
set above, the same as `latest`: `release.yml` calls `packages.yml`, whose own staging and signing
jobs serve the tag ([ADR-0742](adr/0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md)). The Complement step attaches the Debian 13 package it
tested beside it, as `-debian.deb` (`release-process.md`, "Complement").

The OpenBSD package job builds with standalone `pkg_create(1)` (no ports tree),
generating a framework-free packing list from the staged install. The NetBSD
package job assembles the `.tgz` directly with `tar` — NetBSD 10.x's base
`pkg_create` segfaults when scanning hardened ELF binaries under QEMU. The
resulting archive follows the NetBSD package format (`+CONTENTS`, `+COMMENT`,
`+DESC`, `+BUILD_INFO` at the archive root) and is compatible with `pkg_add`.
The checked-in `packaging/openbsd/PLIST` and `packaging/netbsd/Makefile` remain
the ports/pkgsrc recipes for downstream porters and are kept in sync by
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
when static image codecs are unavailable (thumbnail requests are then answered
`404`). Prefer a native Tier 1/Tier 2 package whenever the platform is new
enough; use the static tarball only when it is not.

## Tier 3 — Best-effort (not in CI)

Expected to work but not continuously verified. Issues are accepted but not
release-blocking.

- **HardenedBSD** — uses the FreeBSD `pkg` toolchain and `scripts/build-bsd.sh`.
- **Other Linux distributions** — via the portable static tarball or a from-source build.
- **Windows** — development only, through a Linux or FreeBSD VM over ssh (`python build.py vm`, `--vm <name>` for a second VM) or WSL (`python build.py wsl`). Not a server deployment target.
- **macOS** — not a supported target.

## Per-platform hardening posture

Runtime hardening is platform-specific and reported by the startup self-check
(see [hardening.md](hardening.md)).

| Control | Linux | FreeBSD | OpenBSD | NetBSD |
|---|---|---|---|---|
| seccomp-bpf syscall filter | enabled | n/a | n/a | blocks startup (ADR-0378) |
| Landlock filesystem restriction (federation worker only) | enabled (wired 0.12.13, ADR-0062 part 3) | n/a | n/a | n/a |
| ELF RELRO / BIND_NOW / noexec stack probe | enabled | enabled | enabled | enabled |
| pledge / unveil | n/a | n/a | enabled (wired in 0.10.7) | n/a |
| Capsicum | n/a | enabled (wired in 0.10.7) | n/a | n/a |
| Core-dump policy (`RLIMIT_CORE`) | probed, plus `PR_GET_DUMPABLE` | probed | probed | probed |
| `no_new_privs`, capability bounding set | probed | n/a | n/a | n/a |

Landlock applies only to the federation worker (`merovingian-fed-worker`), not
the main `merovingian-server` process — see [hardening.md](hardening.md),
"What is intentionally deferred". On kernels without Landlock (older than
Linux 5.13, or disabled at boot), the worker refuses to start unless
`federation.worker.allow_without_landlock=true` is set.

The sandboxed thumbnail worker applies its own `setrlimit` clamps and then the
platform sandbox: the seccomp filter on Linux, `pledge("stdio")` on OpenBSD and
Capsicum on FreeBSD. It refuses to decode on a platform with none of these
(NetBSD), so **there are no thumbnails on NetBSD** until privilege separation
comes from outside the server process; thumbnail requests are answered `404`
([ADR-0419](adr/0419-the-thumbnail-decoder-refuses-to-run-without-a-platform-sandbox.md)). NetBSD is also refused at server startup
([ADR-0378](adr/0378-probe-elf-hardening-in-memory-and-keep-netbsd-refused.md)).
OpenBSD packages before 0.12.93 were built without libjpeg-turbo and so shipped
no thumbnail worker, and answered thumbnail requests `404`; from 0.12.93 the
OpenBSD package build fails rather than ship without either worker
([ADR-0650](adr/0650-each-ubuntu-and-opensuse-release-gets-its-own-build-check-and-package.md)).

ClamAV scanning (`security.media.clamd_socket_path`) is refused at startup on
FreeBSD and OpenBSD, because Capsicum and unveil stop the main process from
connecting to the clamd socket
([ADR-0566](adr/0566-the-clamd-socket-is-refused-at-startup-where-the-sandbox-forbids-connecting-to-it.md)).
The check (`media::clamd_supported_on_this_platform`) returns false only on
those two; NetBSD is refused at startup for other reasons (above).

## Changing a platform's tier

Promoting a platform to Tier 1 requires a green build-and-test CI job on that
platform. Demoting requires removing the job and recording the reason in
`CHANGELOG.md`. Keep this document and the `Platform support` row in
[todos/capability-gaps.md](todos/capability-gaps.md) in sync with the actual CI
job set.
