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
| `build-deb.sh` | Builds a `.deb` package |
| `build-rpm.sh` | Builds an `.rpm` package |
| `build-freebsd-pkg.sh` / `build-netbsd-pkg.sh` / `build-openbsd-pkg.sh` | BSD package builds |
| `format_code.py` | Runs `clang-format` over all C++ source and headers |
| `check-catch2-bdd-tests.sh` | Verifies every `SCENARIO` is registered and has at least one `REQUIRE` |
| `check-conformance-gate.sh` | Fails if any conformance test has been removed or commented out |
| `check-unit-test-registration.sh` | Checks that unit test files are registered in `meson.build` |
| `check-release-readiness.sh` | Pre-release checklist: version consistency, changelog entry, no debug flags |
| `reject-unsafe.sh` | Grep-based check for banned patterns (raw `new`, `delete`, `malloc`, `free`) |
| `setup-dev-env.sh` | Installs build dependencies on a fresh Linux dev machine |
| `fetch_matrix_spec.py` | Downloads and unpacks the Matrix spec into `docs/matrix-v1.18-spec/` |

## Rules

- **Do not call build scripts directly** unless you know what you are doing.
  Use `python build.py` (or `python build.py wsl` on Windows) — it handles ordering, flags, and test runs.
- All scripts must be idempotent — running them twice must not cause errors or duplicate work.
- Scripts that modify the working tree (format, rewrite) must print what they changed.
- `reject-unsafe.sh` runs as a pre-commit gate. If it blocks you, fix the code — do not
  add an exception to the script.
