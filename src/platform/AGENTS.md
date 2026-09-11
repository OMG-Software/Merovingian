# src/platform/ — Platform Hardening Module

Runtime security hardening: seccomp syscall filtering, ELF integrity checks, and file metadata safety.
This module is security-critical. Changes here affect the server's attack surface at the OS level.

## Key files

| File | Responsibility |
|---|---|
| `runtime_hardening.cpp` | Applies all hardening controls at startup in the correct order |
| `seccomp_hardening.cpp` | Builds and installs the seccomp-BPF syscall allow-list |
| `hardening_self_check.cpp` | Verifies that hardening controls are active; aborts if a required control failed |
| `elf_probe.cpp` | Checks ELF binary properties (PIE, stack canaries, RELRO, NX) at startup |
| `file_metadata.cpp` | Safe file metadata helpers that avoid TOCTOU races |

## Security rules — non-negotiable

1. **Hardening is applied at startup before any network sockets are opened.**
   If you add a new syscall that is blocked by seccomp, add it to the allow-list in
   `seccomp_hardening.cpp` — do not disable seccomp.

2. **`hardening_self_check` must pass before serving requests.** `main.cpp` refuses to start
   (`runtime_start_error`) unless `HardeningSelfCheck::is_ready()`, which requires every
   control to be `enabled`. A control reported as `unknown` or `disabled` is a production blocker.

3. **`elf_probe` failures block start-up.** If the probe cannot confirm PIE or RELRO, that
   check is set to `unknown`, which `is_ready()` treats as a blocker. Controls that are not
   enabled are logged through `log_diagnostic` (DEBUG by default) and summarised at start-up.

   Off Linux, `runtime_hardening.cpp` applies the platform sandbox instead of seccomp:
   OpenBSD `pledge(2)`, and FreeBSD Capsicum capability mode, which `main.cpp` enters after
   the listeners bind. The federation worker has its own path (`apply_worker_hardening`);
   see `docs/platform-support.md` and ADR-0041.

4. **File paths from config must be validated** before use in `file_metadata.cpp`.
   Never pass user-supplied paths to `open()` or `stat()` without validation.

## Platform support

Seccomp is Linux-only. On other platforms (`__linux__` not defined), the seccomp functions
are no-ops. The self-check adapts accordingly — check `docs/platform-support.md` for the
per-platform hardening matrix.

## Key docs

- `docs/hardening.md` — full hardening control inventory
- `docs/platform-support.md` — per-OS hardening matrix
- `docs/threat-model.md` — OS-level threat assumptions
