# Developer Environment

The repository includes a portable POSIX setup script for Linux and BSD development hosts:

```sh
sh scripts/setup-dev-env.sh
```

It installs the toolchain and development packages needed for the current Meson build, then creates or reconfigures the default `build` directory.

## Supported Hosts

The script supports these package managers:

- Linux: `apt`, `dnf`, `zypper`, `pacman`, `apk`
- BSD: `pkg`, `pkg_add`, `pkgin`

The package set intentionally avoids Boost. It installs C++ toolchains, Meson,
Ninja, pkg-config/pkgconf, Git, Python, Perl, Bison, Flex, M4, TLS headers,
Catch2, clang tooling, and cppcheck. Merovingian now pins libsodium, libcurl,
libpq, SQLite, OpenSSL, Catch2, and yyjson through committed Meson wraps so the
default build path does not depend on host copies of those libraries. `yyjson`
is used for strict JSON parsing; its wrap exposes third-party headers as system
includes so warning-as-error still applies to project code rather than inline C
headers from the dependency checkout. C++ sources include a project-owned
adapter rather than `yyjson.h` directly.

CI runs clang-tidy on changed C++ translation units with parallel per-file log
groups and timeouts. Headers are analyzed transitively through the Meson compile
database instead of being invoked as standalone clang-tidy inputs.
The unsafe source gate is a Bash script and must be run with `bash`, matching
CI, because it relies on strict shell options and portable grep behavior.
OpenSSL is the selected TLS provider and is pinned through
`subprojects/openssl.wrap`. The Linux, BSD, and WSL wrappers now run Meson with
`--wrap-mode=forcefallback` by default, so clean builds resolve the committed
source-pinned subprojects rather than host copies of those libraries.
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
sh scripts/build-linux.sh --builddir build-wsl
```

The WSL setup script installs the compiler, linker, Perl/Bison/Flex toolchain
needed by the wrapped third-party sources, OpenSSL headers, Catch2, clang
tooling, cppcheck, and a current Meson/Ninja virtual environment. The virtual
environment is used because the distribution Meson in Ubuntu 24.04 is too old
to configure the repo's C++26 build.

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

## Build Wrappers

Use the Linux wrapper inside WSL or a native Linux shell to configure, compile,
and test with a C++26-capable Clang toolchain:

```sh
sh scripts/build-linux.sh
```

The default build directory is `build-clang22`, with `CC=clang-22` and
`CXX=clang++-22`. Override these when using another compiler:

```sh
sh scripts/build-linux.sh --builddir build-dev --cc clang-22 --cxx clang++-22
```

From Windows PowerShell, call the WSL wrapper with the distro name that appears
in `wsl -l -v`:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-wsl.ps1 -Distro Ubuntu-24.04
```

Both wrappers use Meson `forcefallback` mode by default so the pinned
dependency wraps are used even when the host has system copies installed.

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

## Security Posture

The setup script does not weaken local package manager policy, add third-party package repositories, install Boost, or fetch dependencies outside the operating-system package manager. Use `--dry-run` during review to record the exact package command before running it on hardened hosts.
