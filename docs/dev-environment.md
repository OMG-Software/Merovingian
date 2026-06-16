# Developer Environment

The repository includes a portable POSIX setup script for Linux and BSD development hosts:

```sh
sh scripts/setup-dev-env.sh
```

It installs the toolchain and development packages needed for the current Meson build, then creates or reconfigures the default `build` directory.

## Supported Hosts

Merovingian is C++26, so the host needs a recent toolchain: **Clang ≥ 18
(`-std=c++26`) or GCC ≥ 14** with the matching C++ standard library, plus
Meson ≥ 1.1.0. Older distributions ship a pre-C++26 compiler and cannot build
the project — see [platform-support.md](platform-support.md) for the minimum
version of each Tier 1 platform and for the static-tarball path for older hosts.

The script supports these package managers:

- Linux: `apt`, `dnf`, `zypper`, `pacman`, `apk`
- BSD: `pkg`, `pkg_add`, `pkgin`

The package set intentionally avoids Boost. It installs C++ toolchains, Meson,
Ninja, pkg-config/pkgconf, Git, Python, Perl, Bison, Flex, M4, OpenSSL,
LibSodium, PostgreSQL client headers, Catch2, clang tooling, and cppcheck.
Merovingian pins libcurl, SQLite, Catch2, and yyjson through committed Meson
wraps so the default build path does not depend on host copies of those
libraries. OpenSSL, LibSodium, and PostgreSQL libpq are resolved from
operating-system packages so security updates can be delivered by the host
package manager. `yyjson` is used for strict JSON
parsing; its wrap exposes third-party headers as system includes so
warning-as-error still applies to project code rather than inline C headers
from the dependency checkout. C++ sources include a project-owned adapter rather
than `yyjson.h` directly.

CI runs clang-tidy on changed C++ translation units with parallel per-file log
groups and timeouts. Headers are analyzed transitively through the Meson compile
database instead of being invoked as standalone clang-tidy inputs.
The unsafe source gate is a Bash script and must be run with `bash`, matching
CI, because it relies on strict shell options and portable grep behavior.
OpenSSL is the selected TLS provider and is intentionally resolved through the
host package manager. The Linux, BSD, and WSL wrappers still run Meson with
`--wrap-mode=forcefallback` by default, but the top-level OpenSSL, LibSodium,
and libpq dependencies disallow fallback so clean builds use OS-provided shared
libraries for those boundaries.
Dependency reviews live under `docs/dependencies/`; new direct dependencies
should add or update a review there before they are wired into Meson.

Linux and BSD CI builds run through the same wrappers intended for local use:

```sh
sh scripts/build-linux.sh --builddir build
sh scripts/build-bsd.sh --builddir build
```

Ubuntu/Debian WSL hosts should first run:

```sh
sh scripts/wsl-setup.sh
export PATH="$HOME/.local/bin:$PATH"
sh scripts/build-wsl.sh
```

`build-wsl.sh` defaults to the `build-wsl` directory and contains NTFS-specific
workarounds.  In particular, automake's `depcomp` bootstrap fails on
NTFS-backed filesystems; the script automatically detects a stale curl
subproject (one configured without `--disable-dependency-tracking`) and wipes
it so Meson re-configures curl with the correct options. It also compares the
extracted `subprojects/curl-<version>/meson.build` against the committed curl
packagefile and re-extracts curl when that copy is stale, including after
`--clean` wipes the build directory. Pass `--clean` to wipe the entire build
directory and start from scratch. The wrapper also stages an executable
`make` shim under the WSL home directory cache before Meson setup so
`external_project` builds do not depend on executable-bit metadata for scripts
stored under `/mnt/c`. The staged shim is rewritten with LF line endings so
its `#!/bin/sh` shebang remains executable on Linux.

From Windows, use the launcher wrappers instead of typing the full `wsl.exe`
command manually:

```powershell
.\build-wsl.cmd
.\build-wsl.cmd -Distro Ubuntu-24.04 -CompileOnly
```

`build-wsl.cmd` forwards its arguments to `scripts/build-wsl.ps1`, and the
PowerShell bridge enters the default WSL distro unless `-Distro` is provided,
then runs `sh ./scripts/build-wsl.sh` from the repository root. This keeps
Windows-triggered builds on the same WSL build path as an interactive Linux
shell.

The WSL setup script installs the compiler, linker, Perl/Bison/Flex toolchain
needed by the wrapped third-party sources, OpenSSL, LibSodium, PostgreSQL
client headers, Catch2, clang tooling, cppcheck, and a current Meson/Ninja
virtual environment. The virtual environment is used because the distribution
Meson in Ubuntu 24.04 is too old to configure the repo's C++26 build.

Project-owned headers should use quoted includes. Use the rewrite helper to
convert angle-bracket Merovingian includes in source trees:

```sh
python3 scripts/rewrite_merovingian_includes.py include src tests
```

Check mode reports pending rewrites without modifying files:

```sh
python3 scripts/rewrite_merovingian_includes.py --check include src tests
```

## Common Usage

Preview the commands without installing packages:

```sh
sh scripts/setup-dev-env.sh --dry-run
```

Install packages and configure the default build directory:

```sh
sh scripts/setup-dev-env.sh
```

Check an existing machine without installing packages:

```sh
sh scripts/setup-dev-env.sh --check-only
```

Use a dedicated build directory:

```sh
sh scripts/setup-dev-env.sh --builddir build/dev
```

Skip package installation when dependencies are already managed externally:

```sh
sh scripts/setup-dev-env.sh --no-install
```

## Unified Build Script

`build.py` is the single entry point for configuring, compiling, and testing
on every supported platform. It delegates to the shell scripts in `scripts/`
and handles Meson setup, compilation, and testing in one step.

```sh
# Linux
python build.py linux

# BSD
python build.py bsd

# WSL (Windows Subsystem for Linux)
python build.py wsl

# AddressSanitizer + UBSan through WSL
python build.py wsl --builddir build-asan --buildtype debug --sanitize address,undefined

# ThreadSanitizer through WSL
python build.py wsl --builddir build-tsan --buildtype debug --sanitize thread
```

### Packaging targets

```sh
python build.py deb        # Ubuntu/Debian .deb package
python build.py rpm        # Fedora RPM package
python build.py pkg        # FreeBSD .pkg package
python build.py static     # Portable static Linux tarball (musl)
```

CI also produces distro-specific packages via dedicated scripts:

```sh
sh scripts/build-deb.sh           # Debian .deb (also used by deb CI job)
sh scripts/build-rhel-rpm.sh      # RHEL-compatible RPM (AlmaLinux 10)
sh scripts/build-opensuse-rpm.sh  # OpenSUSE Tumbleweed RPM
sh scripts/build-openbsd-pkg.sh   # OpenBSD .tgz (run inside OpenBSD)
sh scripts/build-netbsd-pkg.sh    # NetBSD .tgz (run inside NetBSD)
```

### Common development options

```sh
# Change build directory
python build.py linux --builddir build-dev

# Use a hardened build profile
python build.py linux --profile hardened

# Use the named sanitizer profile on WSL (defaults to address,undefined)
python build.py wsl --profile sanitizer

# Skip tests (compile only)
python build.py wsl --no-tests

# Wipe and reconfigure (WSL only)
python build.py wsl --clean

# Specify WSL distro
python build.py wsl --distro Ubuntu-24.04

# Preview commands without running them
python build.py linux --dry-run

# Set up build directory without compiling
python build.py linux --setup-only

# Compile without running tests or reconfiguring
python build.py linux --compile-only
```

Run `python build.py --help` for the full option reference.

`build.py` internally calls the shell scripts described in the Build Wrappers
section below. Use the scripts directly only when you need script-specific
options not exposed by `build.py`.

## Build Wrappers

Use the Linux wrapper on a native Linux shell to configure, compile, and test
with a C++26-capable Clang toolchain:

```sh
sh scripts/build-linux.sh
```

The default build directory is `build`, with `CC=clang` and `CXX=clang++`.
Override these when using another compiler:

```sh
sh scripts/build-linux.sh --builddir build-dev --cc clang-22 --cxx clang++-22
```

Inside WSL use the dedicated WSL wrapper instead:

```sh
sh scripts/build-wsl.sh
```

The default build directory is `build-wsl`.  The script automatically handles
NTFS-specific issues (see the WSL section above).  Pass `--clean` to force a
full rebuild.

From Windows, `.\build-wsl.cmd` is the matching entrypoint; it forwards all
arguments to `scripts/build-wsl.ps1`, which then invokes `scripts/build-wsl.sh`
inside the default WSL distro unless `-Distro` overrides it.

All wrappers use Meson `forcefallback` mode by default so pinned dependency
wraps are used even when the host has system copies installed. OpenSSL,
LibSodium, and PostgreSQL libpq are excluded from that policy and are resolved
from the host package manager.

Meson launches repository shell-based source gates through `sh`, which keeps
WSL builds on `/mnt/c` independent of Windows executable-bit metadata.

Smoke tests that need Unix file modes create their fixtures under the WSL
temporary directory instead of the Windows-mounted build directory. This keeps
the server's permission checks enabled while avoiding DrvFS `chmod` failures.
The smoke-test Meson file keeps shared shell fragments as single expressions so
the Ubuntu 24.04 Meson parser accepts them during setup.

Clang 22 builds keep `-Werror` enabled, but suppress the narrow
`-Wc2y-extensions` diagnostic because Catch2 uses `__COUNTER__` for test
registration.

## BSD Notes

FreeBSD and HardenedBSD use `pkg`. OpenBSD uses `pkg_add`. NetBSD prefers `pkgin` and falls back to `pkg_add` when available.

Some BSD releases ship a base compiler and package LLVM separately. The script installs the packaged LLVM toolchain so clang-format, clang-tidy, and current C++ compiler support are available for project checks.

FreeBSD, OpenBSD, and NetBSD are Tier 1 platforms: each builds and runs the full
test suite per pull request through `scripts/build-bsd.sh` on a CI VM. See
[platform-support.md](platform-support.md) for the full support-tier matrix and
per-platform hardening posture.

## Security Posture

The setup script does not weaken local package manager policy, add third-party package repositories, install Boost, or fetch dependencies outside the operating-system package manager. Use `--dry-run` during review to record the exact package command before running it on hardened hosts.
