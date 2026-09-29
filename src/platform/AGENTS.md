# src/platform/ — Platform Hardening Module

Runtime security hardening: seccomp syscall filtering, ELF integrity checks, and file metadata safety.
This module is security-critical. Changes here affect the server's attack surface at the OS level.

## Key files

| File | Responsibility |
|---|---|
| `runtime_hardening.cpp` | Applies all hardening controls at startup in the correct order |
| `seccomp_hardening.cpp` | Builds and installs the seccomp-BPF syscall allow-list (always with `SECCOMP_FILTER_FLAG_TSYNC`), and probes every task's `Seccomp:`/`NoNewPrivs:` state |
| `landlock_hardening.cpp` | ADR-0062 part 3: builds and installs the federation worker's Linux Landlock filesystem ruleset (`apply_worker_landlock`); real syscalls sit behind an injectable `LandlockHardeningOps` table, mirroring `media::DecoderHardeningOps` |
| `signal_hardening.cpp` | `ignore_sigpipe()`: `sigaction(SIGPIPE, SIG_IGN)`, called first in every executable's `main()` (HTTP-5) |
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

5. **`apply_worker_landlock` is Linux-only, worker-specific, and fail-closed like
   `apply_worker_hardening`.** It is called from `federation_worker::main()`
   before the worker seccomp filter (Landlock's syscalls are not on that
   filter's allowlist) and before the event loop opens the database or
   handles any inbound request. Any failure other than "this kernel has no
   Landlock" (ENOSYS/EOPNOTSUPP/ABI < 1) is always fatal, even when
   `federation.worker.allow_without_landlock=true` — see ADR-0062 part 3.
   Add a path to the allowlist only in `build_worker_landlock_rules()`,
   sourced from the worker's own config copy or a documented, best-effort
   fixed system path — never hard-code a secret file path there.

6. **No thread may exist before Landlock and the seccomp filter are installed (ISO-1,
   [ADR-0082](../../docs/adr/0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md)).**
   Both attach to the calling thread only, and Landlock has no thread-sync flag on older
   kernels, so a thread started earlier escapes it. The logger is the usual culprit:
   `SingleLog` starts no thread until `start_writers()`, which the worker and the server call
   only after hardening. Before adding any code that starts a thread (a pool, a timer, a
   library helper), check it cannot run before a hardening call in any process that hardens
   itself.
7. **Every seccomp filter is installed with `SECCOMP_FILTER_FLAG_TSYNC`, through the
   `seccomp()` syscall, and any result other than 0 is a failure** (with TSYNC the kernel
   returns the id of a thread it could not synchronise, which is positive). Never add a
   fallback that installs on the calling thread only, and never install with flags 0.
8. **The self-check inspects every task.** `probe_seccomp_status()` reads
   `/proc/self/task/<tid>/status` and reports `seccomp_active` only when all tasks have
   `Seccomp: 2` and `NoNewPrivs: 1`; a task that cannot be read counts as unconfined.
   `/proc/self/status` shows only the thread-group leader and must not be used for this. Note
   that after `apply_worker_landlock()` the worker cannot open `/proc`, so the worker does not
   run this probe itself; the forked test in `tests/unit/test_worker_hardening_threads.cpp`
   covers it.
9. **`ignore_sigpipe()` is the first call in every executable's `main()`** (server,
   federation worker, thumbnail worker, `db-migrate`), before any thread and before any
   seccomp filter, and a failure exits non-zero. It is not an optional control: OpenSSL's
   socket BIO writes without `MSG_NOSIGNAL`, so the default disposition lets one TLS client
   that resets its connection kill the process (HTTP-5).

## Platform support

Seccomp is Linux-only. On other platforms (`__linux__` not defined), the seccomp functions
are no-ops. Landlock (`landlock_hardening.cpp`) is likewise Linux-only and, unlike seccomp, is
applied only to the federation worker, not the main process — the self-check adapts accordingly.
Check `docs/platform-support.md` for the per-platform hardening matrix.

## Key docs

- `docs/hardening.md` — full hardening control inventory
- `docs/platform-support.md` — per-OS hardening matrix
- `docs/threat-model.md` — OS-level threat assumptions
