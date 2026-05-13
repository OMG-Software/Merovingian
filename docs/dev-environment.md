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
Ninja, pkg-config/pkgconf, Git, Python, libsodium, PostgreSQL client headers,
SQLite, TLS headers, Catch2, clang tooling, and cppcheck. `yyjson` is used for
strict JSON parsing; Meson uses a pinned wrap fallback when the host does not
provide a `yyjson` pkg-config module. The fallback exposes yyjson headers as
system includes so Merovingian's warning-as-error policy applies to project
code without turning third-party C inline headers into CI blockers. C++ sources
include a project-owned adapter rather than `yyjson.h` directly.

CI runs clang-tidy on changed C++ translation units with parallel per-file log
groups and timeouts. Headers are analyzed transitively through the Meson compile
database instead of being invoked as standalone clang-tidy inputs.
The unsafe source gate is a Bash script and must be run with `bash`, matching
CI, because it relies on strict shell options and portable grep behavior.
OpenSSL is included as a system dependency in Meson so platform headers are not
held to Merovingian's project warning-as-error policy.

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

Both wrappers use Meson wrap fallback mode by default so the pinned Catch2
subproject can be fetched when the system package is unavailable.
The Linux wrapper checks for the required `libsodium`, `openssl`, and `sqlite3`
pkg-config modules before configuring Meson so missing system development
packages fail before a partial build starts.

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
