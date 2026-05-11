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

The package set intentionally avoids Boost. It installs C++ toolchains, Meson, Ninja, pkg-config/pkgconf, Git, Python, libsodium, PostgreSQL client headers, SQLite, TLS headers, Catch2, clang tooling, and cppcheck.

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

## BSD Notes

FreeBSD and HardenedBSD use `pkg`. OpenBSD uses `pkg_add`. NetBSD prefers `pkgin` and falls back to `pkg_add` when available.

Some BSD releases ship a base compiler and package LLVM separately. The script installs the packaged LLVM toolchain so clang-format, clang-tidy, and current C++ compiler support are available for project checks.

## Security Posture

The setup script does not weaken local package manager policy, add third-party package repositories, install Boost, or fetch dependencies outside the operating-system package manager. Use `--dry-run` during review to record the exact package command before running it on hardened hosts.
