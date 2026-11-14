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
Merovingian pins SQLite, Catch2, and yyjson through committed Meson wraps so
the default build path does not depend on host copies of those libraries.
OpenSSL, LibSodium, PostgreSQL libpq, and libcurl are resolved from
operating-system packages so security updates can be delivered by the host
package manager. The libcurl wrap is used only when the build sets
`-Dstatic_curl_wrap=true` (the static musl build). The thumbnail worker also
uses the optional host libraries `libpng16` and `libturbojpeg`; it is built only
when both are found. `yyjson` is used for strict JSON
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
libpq, and libcurl dependencies disallow fallback (libcurl allows it only with
`-Dstatic_curl_wrap=true`), and the optional `libpng16` and `libturbojpeg`
have no wrap, so clean builds use OS-provided shared libraries for those
boundaries.
Dependency reviews live under `docs/dependencies/`; new direct dependencies
should add or update a review there before they are wired into Meson.

## Line Endings

`.gitattributes` checks out every text file with LF on every platform
(`* text=auto eol=lf`), whatever `core.autocrlf` is set to; only the
Windows-only `*.ps1` and `*.cmd` scripts check out with CRLF (ADR-0158). The
tree is built and tested under Linux, WSL or a BSD, tests read unit files,
scripts and sources as text, and packages ship files straight from the
checkout, so a CRLF working copy fails tests and would ship broken files.

A checkout made before 0.12.27 keeps whatever endings it was written with,
since Git rewrites a file only when it changes. Re-check it out once (commit or
set aside your work first):

```bash
git ls-files -z | xargs -0 rm -f && git checkout -- .
```

`git ls-files --eol` then shows `w/lf` for everything but those two script
types. `tests/tooling/test_line_endings.py` (Meson test `line-endings-tooling`)
checks the attributes; it skips itself where Git cannot read the checkout, such
as a worktree created by Windows Git and opened from WSL, whose `.git` file
names a `C:/` path.

## Git Hooks

Install the repository Git hooks from the project root:

```sh
sh scripts/install-hooks.sh
```

The pre-commit hook runs the unsafe C/C++ source gate, the Catch2 BDD style
gate, the unit/conformance test registration gate, and a staged-file check that
requires project changes to include both `CHANGELOG.md` and a relevant
`docs/*.md` update. Set `MEROVINGIAN_SKIP_CHANGE_DOC_CHECK=1` only for reviewed
non-behavioural maintenance commits.

The project also carries a Codex `PostToolUse` hook in `.codex/hooks.json`.
After Codex edit/write tool calls, it runs `.codex/hooks/clang_format_after_edit.py`
to apply `clang-format -i` to edited C and C++ source files. Codex requires
project-local command hooks to be reviewed and trusted before they run.

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

### Building on a VM

`python build.py vm` builds and tests on a Linux or FreeBSD virtual machine (or
any such host) over ssh, from Windows or any other host with Python, Git and
OpenSSH. The VM's native file system avoids every NTFS workaround above, and a
build there does not compete with the editor for the Windows host's memory.
See [ADR-0752](adr/0752-build-py-vm-syncs-the-working-tree-over-ssh-and-runs-build-linux-sh.md).

Each run:

1. Lists the files to send: every tracked file as it is on disk (uncommitted
   edits included, with Git's executable bit), and every untracked file Git does
   not ignore, except under a top-level name starting with `build` or `.`.
2. Reads the manifest the VM kept from the last run and sends, as one tar stream
   over ssh, only the files whose mode, size or modification time differ. Files
   the last manifest listed and this one does not are deleted on the VM before
   the archive is unpacked, so a file that became a directory, or the reverse,
   never blocks it. If another run changed the manifest between this run reading
   it and taking the lock, the VM touches nothing and `build.py vm` reads the
   manifest again and resends (three attempts). A sync cut off part-way leaves
   the manifest listing every path with no metadata, so the next run resends
   each file and still deletes what it no longer has.
3. Takes the ssh user's lock (`~/merovingian-vm/.lock`, through `python3`'s
   `fcntl.flock`, since the BSDs have no `flock` command), so a second run as
   that user, from any checkout, waits ("another run holds the VM lock"), then
   runs the host's build script in
   `~/merovingian-vm/<checkout name>-<hash of its path>`, one directory per local
   checkout or worktree: `scripts/build-linux.sh` where `uname -s` says `Linux`,
   `scripts/build-bsd.sh` where it says `FreeBSD`, `OpenBSD`, `NetBSD` or
   `DragonFly`; any other system is refused. The lock does not cover other users
   on the VM: use one VM user for every run, since two suites at once time out
   unrelated tests.
4. Copies `meson-logs/testlog.txt` and `testlog.json` back to the same build
   directory locally, `build-vm/meson-logs/` by default (`build-vm-<name>/` for
   a named VM), and prints the `Ok:`, `Fail:` and `Timeout:` counts. It deletes
   the local and the VM's previous logs before anything is unpacked, so a run
   that fails before testing leaves no log, never an old one. Each run copies
   its logs, still under the lock, into a directory of its own on the VM
   (`.vm-sync/run-<token>/`) and fetches them from there, so a run that starts
   the moment this one ends cannot replace them first. If the logs cannot be
   copied back (ssh refuses the key, say), it says so, names where they are on
   the VM, and exits non-zero even when the build passed.

The exit status is the build's. Because the VM-side build directory and the
local one share a name, `build-vm/meson-logs/testlog.txt` is read the same way
as any other build's log.

One-time setup:

1. Create a key for the build only and add its public half to the VM user's
   `~/.ssh/authorized_keys`:

   ```sh
   ssh-keygen -t ed25519 -N '' -C merovingian-vm-build -f ~/.ssh/merovingian_vm_ed25519
   ```

2. Connect once with `ssh` and check the host key fingerprint against the VM's
   console (`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`). `build.py vm`
   runs ssh with `StrictHostKeyChecking=yes` and `BatchMode=yes`: it never
   accepts an unknown or changed host key and never prompts.
3. Write the settings to `~/.config/merovingian/vm.ini` (or the file
   `MEROVINGIAN_VM_CONFIG` names). The file lives outside the repository, so
   every worktree reads it and no address is committed:

   ```ini
   [vm]
   host = 192.0.2.10
   user = builder
   identity = ~/.ssh/merovingian_vm_ed25519
   # port = 22
   # jobs = 4
   ```

   `--host`, `--user`, `--port`, `--identity` and `--jobs` override the file, and
   `MEROVINGIAN_VM_HOST`, `MEROVINGIAN_VM_USER`, `MEROVINGIAN_VM_PORT`,
   `MEROVINGIAN_VM_IDENTITY` and `MEROVINGIAN_VM_JOBS` override it when no flag
   is given. An unknown key in `[vm]` is an error.

   More VMs go in sections named `[vm.<name>]` (lower-case letters, digits, `-`
   and `_`), chosen with `--vm <name>` or `MEROVINGIAN_VM_NAME`. A named VM reads
   only its own section, never `[vm]`, and a name with no section is an error.
   Its default build directory is `build-vm-<name>`, so each VM's logs stay
   apart locally:

   ```ini
   [vm.freebsd]
   host = 192.0.2.11
   user = builder
   identity = ~/.ssh/merovingian_bsd_ed25519
   ```

4. Install the packages on the VM before the first sync, as root or a user who
   can use `sudo` or `doas`. `build.py vm` takes its lock through `python3`, so
   a VM without it cannot be synced yet: copy the setup script over on its own,
   run it there, then sync once to check:

   ```sh
   scp scripts/remote-host-setup.sh builder@192.0.2.10:
   ssh -t builder@192.0.2.10 sh remote-host-setup.sh
   python build.py vm --exec true
   ```

   On FreeBSD, `pkg install python3` from the console does as well for the
   first sync; the setup script can then run from the synced checkout.

   `scripts/remote-host-setup.sh` prepares a remote build host, the VM or
   another machine (`scripts/wsl-setup.sh` is for WSL only). It accepts Ubuntu,
   Debian, distributions whose `ID_LIKE` names either, such as Linux Mint, and
   FreeBSD. On the Debian family it installs with `apt-get` the compiler, linker
   and every library `build-linux.sh` checks for, including libcurl, libpng and
   libjpeg-turbo, and installs Meson 1.11 or later and Ninja in a virtual
   environment linked into `~/.local/bin`, because Ubuntu 24.04's Meson is too
   old for the C++26 build. `build.py vm` puts `~/.local/bin` first on `PATH`
   for the build. On FreeBSD it installs with `pkg` the packages the FreeBSD CI
   job installs, Meson and Ninja among them, plus `python3`. `--dry-run` prints
   the commands; re-running it is safe.

Usage:

```sh
# Full build and test suite in build-vm
python build.py vm

# The same on the [vm.freebsd] VM, in build-vm-freebsd
python build.py vm --vm freebsd

# Other build-linux.sh options work as they do for linux
python build.py vm --builddir build-vm-asan --profile sanitizer
python build.py vm --clean --compile-only

# Sync, then run one command in the VM checkout instead of building; --exec comes last
python build.py vm --exec ./build-vm/tests/merovingian-unit-tests "[push]"
```

`--exec` runs with `MEROVINGIAN_TEST_DISABLE_HARDENING=1`, as `meson test` does,
under the same lock. `--dry-run` reads the VM's manifest and prints the number of
files it would send and the script the VM would run, without sending anything.

Without `--jobs`, a run compiles and tests with one job per 1.5 GiB of the VM's
memory (`/proc/meminfo` on Linux, `sysctl hw.physmem` on the BSDs), never more
than its CPUs: a C++26 translation unit here can take over
1 GiB to compile, and Meson's default of one job per CPU runs a small VM out of
memory. Give the VM memory rather than lowering `--jobs` where you can.

The `--builddir` must be a relative path whose first part starts with `build`,
so the sync never sends it. PostgreSQL integration tests run only when
`MEROVINGIAN_TEST_POSTGRESQL_URI` is set on the VM, as on any other host. If
ssh drops mid-run, the build keeps running on the VM and holds the lock until it
ends; the next run waits for it.

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

# A Linux or FreeBSD VM over ssh (see "Building on a VM")
python build.py vm

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
sh scripts/build-opensuse-rpm.sh  # OpenSUSE Tumbleweed RPM (MEROVINGIAN_RPM_DIST=.leap16 on Leap 16.0)
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
`--jobs <n>` caps both the compile jobs and the tests run at once (`build.py
linux --jobs` and `build.py vm` pass it on; `build-bsd.sh` and `build.py bsd`
take it too); without it Meson picks its own.
Override the compiler when using another one:

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
LibSodium, PostgreSQL libpq, and libcurl (except with `-Dstatic_curl_wrap=true`)
are excluded from that policy and are resolved from the host package manager,
as are the optional `libpng16` and `libturbojpeg` for the thumbnail worker.

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

`scripts/reject-unsafe.sh` (the pre-commit safety gate) needs a grep with `-P`. The BSD base greps
have none, so install GNU grep (the `ggrep` package; the gate uses it automatically). Without it the
gate refuses to run rather than passing without checking. Its tooling test skips its rule tests on
such a host and checks only that refusal.

FreeBSD, OpenBSD, and NetBSD are Tier 1 platforms: each builds and runs the full
test suite per pull request through `scripts/build-bsd.sh` on a CI VM. See
[platform-support.md](platform-support.md) for the full support-tier matrix and
per-platform hardening posture.

## Documentation Site

The documents under `docs/` are published to
<https://omg-software.github.io/Merovingian/> with MkDocs Material, configured
by `mkdocs.yml` in the repository root. The
[documentation site workflow](../.github/workflows/pages.yml)
builds the site with `--strict` on every branch and pull request and keeps the
rendered site as the `docs-site` workflow artifact; only `main` deploys to
Pages ([ADR-0101](adr/0101-build-the-documentation-site-on-every-branch-but-publish-only-from-main.md)).

To build and preview it locally with the same pinned dependencies CI uses:

```bash
python3 -m venv .venv-docs
.venv-docs/bin/pip install --require-hashes --only-binary :all: -r requirements-docs.txt
.venv-docs/bin/mkdocs build --strict
.venv-docs/bin/mkdocs serve
```

PyPI has no FreeBSD, OpenBSD or NetBSD wheels for PyYAML, MarkupSafe or watchdog, so on a BSD
host `--only-binary :all:` refuses them. Drop that option there: `--require-hashes` still pins
the exact sdist, whose hash is in the lock, but its build script runs during installation, which
CI never allows (ADR-0313).

What the site expects of each branch:

- **A new document needs a navigation entry.** Add it to `nav` in `mkdocs.yml`,
  or to `exclude_docs` if it should not be published. `docs-site-tooling`
  (`tests/tooling/test_docs_site.py`) fails otherwise. ADR records are the
  exception: the ADR index links to them.
- **Link as you would in the repository.** Relative links to files outside
  `docs/` (source, workflows, module `AGENTS.md` files) are rewritten by
  `scripts/mkdocs_site_hooks.py` to open on GitHub at the commit the site was
  built from. Links into `docs/matrix-v1.19-spec/` open the same section of
  the published v1.19 specification.
- **Broken links fail the build.** A link whose target exists nowhere in the
  repository, or an anchor that does not exist on the target page, is a
  strict-mode warning.
- **The changelog page is `CHANGELOG.md`.** The hooks publish it as
  `changelog.md`; do not create that file under `docs/`.
- **The theme is OMG Software's.** Colours live in `docs/stylesheets/extra.css`,
  not in Material palette names; the site opens dark, uses system fonts and
  loads nothing from another origin
  ([ADR-0223](adr/0223-the-documentation-site-wears-the-omg-software-theme-dark-first-with-system-fonts.md)).
  `docs-site-tooling` checks text and link contrast in both schemes.
- **Use the published brand marks.** `docs/assets/omg-logo.svg` and
  `omg-favicon.svg` reproduce the angular OMG mark and favicon from
  [OMG Software](https://omg-software.org/projects/merovingian/index.html).
  The home page uses its separate `merovingian-logo.svg` project mark.
  These SVG files are local, so readers make no request to the organisation site.

## Complement

Running Complement against a package (`scripts/run_complement.py`, see
`tests/complement/AGENTS.md`) needs, beyond the build tools:

- Docker 20.10 or later, with a daemon the user can reach. On Linux, Complement
  maps `host.docker.internal` to the host itself (`host-gateway`). Docker
  Desktop resolves the name natively.
- Go at least the version `tests/complement/run.toml` pins (`go = ...`, the
  `go` directive of Complement's `go.mod` at the pinned commit).
- git, gpg and the GitHub CLI (`gh`, for `gh attestation verify`), and the
  maintainer key imported for a signed run (docs/release-process.md,
  "Verifying release signatures").
- Network access to fetch Complement and its Go modules.

Nothing here is needed for the normal build and test cycle. CI does not run
Complement. Its `complement-image` job only boots the image.

## Security Posture

The setup script does not weaken local package manager policy, add third-party package repositories, install Boost, or fetch dependencies outside the operating-system package manager. Use `--dry-run` during review to record the exact package command before running it on hardened hosts.
