# scripts/ — Build and Development Scripts

Utility scripts for building, formatting, linting, and dev environment setup.
The canonical build entry point is `build.py` in the project root — most scripts are
called by it rather than directly.

## Key scripts

| Script | Purpose |
|---|---|
| `build-linux.sh` | Linux release build (Meson + Ninja) |
| `build-wsl.sh` / `build-wsl.ps1` | WSL build wrapper (runs the Linux build inside WSL from Windows) |
| `build-static-linux.sh` | Fully static Linux binary (musl) |
| `build-bsd.sh` | POSIX-sh build/test driver for BSD hosts (FreeBSD/NetBSD/OpenBSD): configures Meson with system libsodium/openssl/libpq/libcurl, supports named profiles (`debug`, `release`, `sanitizer`, `coverage`, `fuzz`, `hardened`), and runs `meson test` with hardening disabled in-process for the Catch2 runner |
| `build-deb.sh` | Builds a `.deb` package |
| `build-rpm.sh` | Builds an `.rpm` package (Fedora-family default spec) |
| `build-opensuse-rpm.sh` | Builds an `.rpm` for OpenSUSE Tumbleweed from `packaging/opensuse/merovingian.spec` (OpenSUSE package names); forces the `.opensuse` dist tag so the filename doesn't collide with the Fedora/RHEL RPMs |
| `build-rhel-rpm.sh` | Builds an `.rpm` for RHEL 10 / AlmaLinux 10 from `packaging/rhel/merovingian.spec`, which omits `catch-devel` (unreliable in EPEL 10 and unneeded with `-Dbuild_tests=false`) |
| `build-freebsd-pkg.sh` / `build-netbsd-pkg.sh` / `build-openbsd-pkg.sh` | BSD package builds |
| `format_code.py` | Runs `clang-format` over all C++ source and headers |
| `check-catch2-bdd-tests.sh` | Verifies every `SCENARIO` is registered and has at least one `REQUIRE` |
| `check-conformance-gate.sh` | Fails if any conformance test has been removed or commented out |
| `check-elf-hardening.sh` | Build-time hardening gate: inspects a built ELF binary's headers with `readelf` and fails if PIE (`ET_DYN`), `PT_GNU_RELRO`, `DT_BIND_NOW`, or a non-executable stack (`PT_GNU_STACK` without `E`) is missing; the CI-time counterpart to the runtime self-check in `src/platform/`, since that check can only run inside a live, correctly-privileged `merovingian-server` process. Pass `--static` for the static-PIE binary, which has no `PT_DYNAMIC` section to apply `BIND_NOW` to |
| `check-staged-changelog-docs.sh` | Pre-commit guard requiring staged project changes to include `CHANGELOG.md` and relevant `docs/*.md` updates |
| `check-unit-test-registration.sh` | Checks that unit test files are registered in `meson.build` |
| `check-release-readiness.sh` | Pre-release checklist: version consistency, changelog entry, no debug flags |
| `collect-release-evidence.sh` | Appends one platform's release-evidence Markdown section (compiler version, link-time hardening flags plus `check-elf-hardening.sh` output, pinned `subprojects/*.wrap` versions, `testlog.txt` Ok/Fail/Timeout summary, the fuzz targets covered by `run-fuzz-targets.sh`) to a file; run once per platform build job in CI and concatenated into the published release notes |
| `generate-license-summary.py` | Parses the Markdown tables in `docs/dependencies/licenses.md` and writes an equivalent JSON summary (to a given path or stdout), so the human-readable and machine-readable license artifacts stay in sync |
| `generate-matrix-v119-spec-doc.mjs` | Node script that fetches (or reads) the Matrix Client-Server OpenAPI document and regenerates `docs/matrix-v1.19-client-server-api.md`: a generated per-tag endpoint reference table with method/path/operation ID/auth/request/response columns, plus the source URL and SHA-256. Not the same as `fetch_matrix_spec.py`, which mirrors the human-readable spec prose |
| `reject-unsafe.sh` | Grep-based check for banned patterns (raw `new`, `delete`, `malloc`, `free`) |
| `repoint_spec_links.py` | Rewrites `https://spec.matrix.org/v1.19/...` links in `.md`/`.cpp`/`.hpp` files into relative paths against the local mirror in `docs/matrix-v1.19-spec/`, preserving markdown link text and any `#anchor` |
| `reproducible-build.sh` | Runs `build-static-linux.sh` twice with a fixed `SOURCE_DATE_EPOCH` and build directory, then compares SHA-256 hashes of the resulting tarball to verify the static Linux fallback build is byte-for-byte reproducible |
| `rewrite_merovingian_includes.py` | Rewrites `#include <merovingian/...>` angle-bracket includes to `#include "merovingian/..."` quoted form across `include/`, `src/`, `tests/`; supports `--check` (exit 1 if any file needs rewriting, used as a CI gate) and `--dry-run` |
| `run-fuzz-targets.sh` | Builds the libFuzzer harnesses (`-Dbuild_fuzz=true`, clang required) and runs each registered fuzz target for a bounded wall-clock duration under ASan/UBSan, seeded from `tests/fuzz/corpus/`; exits non-zero on the first finding so CI fails fast — a regression gate, not exhaustive corpus generation |
| `install-hooks.sh` | Installs the tracked Git hook templates into `.git/hooks` |
| `setup-dev-env.sh` | Installs build dependencies on a fresh Linux dev machine |
| `validate-phase1-config.sh` | Smoke-tests `merovingian-server --dry-run` against the default config and `config/merovingian.conf.example`, then asserts a config missing required Phase 1 keys is rejected |
| `verify-wrap-pins.sh` | Dependency-lockfile gate over `subprojects/*.wrap`: fails if a wrap is not a `[wrap-file]` entry, is missing `source_hash`, has a `source_hash` that isn't a 64-character lowercase hex string, or uses a `[wrap-git]` entry (forbidden — tags are mutable and shallow clones are non-deterministic) |
| `wsl-setup.sh` | One-time Ubuntu/Debian-WSL bootstrap: installs build packages via `apt-get`, then creates a Python venv under `~/.local/share/merovingian-tools` with pinned Meson/Ninja and symlinks them onto `~/.local/bin`, so the WSL build doesn't depend on distro-packaged Meson versions |
| `fetch_matrix_spec.py` | Downloads and unpacks the Matrix spec into `docs/matrix-v1.19-spec/` |
| `hooks/pre-commit` | The Git hook template installed by `install-hooks.sh`; runs `reject-unsafe.sh`, `check-catch2-bdd-tests.sh`, `check-unit-test-registration.sh`, and `check-staged-changelog-docs.sh` against the repo root before allowing a commit |
| `tool-shims/make` | `PATH` shim so build steps that invoke `make` transparently get GNU Make: execs `gmake` when present (BSD hosts, where the system `make` is not GNU Make), otherwise falls back to `/usr/bin/make`; forwards `DESTDIR` when set |

## Rules

- **Do not call build scripts directly** unless you know what you are doing.
  Use `python build.py` (or `python build.py wsl` on Windows) — it handles ordering, flags, and test runs.
- All scripts must be idempotent — running them twice must not cause errors or duplicate work.
- Scripts that modify the working tree (format, rewrite) must print what they changed.
- `reject-unsafe.sh` runs as a pre-commit gate. If it blocks you, fix the code — do not
  add an exception to the script.
