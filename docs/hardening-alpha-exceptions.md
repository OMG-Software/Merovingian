# Hardening alpha exceptions

The Merovingian's startup hardening self-check (`run_startup_hardening_self_check`,
defined in [`include/merovingian/platform/hardening_self_check.hpp`](../include/merovingian/platform/hardening_self_check.hpp))
reports each defence as `enabled`, `disabled`, `unknown`, or `alpha_exception`.

`alpha_exception` is the explicit alpha-only carve-out the project uses in place
of placeholder `unknown` statuses. Each exception:

- is allowed to exist at startup during alpha (`is_alpha_ready()` returns `true`),
- blocks production readiness (`is_production_ready()` returns `false`),
- carries a human-readable `note` describing what is deferred and pointing back
  to this document.

A `disabled` control is always a hard failure. `run_server` refuses to bind
listeners if any check reports `disabled`.

## Current alpha exceptions

| Check | Reason | Beta/Production plan |
| --- | --- | --- |
| `compiler hardening` (when compiler did not advertise SSP + FORTIFY + PIE macros) | Toolchain may build without all three macros under unusual cross-compiles. The project's `meson.build` still requests them. | Fail closed in CI on toolchains that drop any of `__SSP__`, `_FORTIFY_SOURCE`, `__PIE__`. |
| `linker hardening` | Runtime ELF program-header probe is not yet implemented. The `meson.build` link line still requests `-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack`. | Add a startup probe that parses `PT_GNU_RELRO` / `PT_GNU_STACK` / `DT_BIND_NOW` of the running binary. |
| `RELRO` | Same ELF probe as `linker hardening`. | Same. |
| `seccomp` | Linux seccomp-bpf filter is not applied inside the process during alpha. | Wire a syscall allow-list via `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SECCOMP_SET_MODE_FILTER, …)` before listeners open. |
| `pledge/unveil` | OpenBSD pledge/unveil are scaffolded but not invoked at startup. | Call `pledge("stdio rpath wpath cpath inet …", NULL)` and `unveil` per documented surface. |
| `capsicum` | FreeBSD Capsicum capability mode entry is not yet wired into startup. | Call `cap_enter()` after listeners bind and before request handling. |
| `privilege drop` | Privilege drop is delegated to the service manager (systemd `User=`, OpenRC `user=`, rc.d `_user`) during alpha. | Add an in-process `setresgid`/`setresuid` step gated by configuration. |
| `filesystem restrictions` | Filesystem confinement is delegated to systemd sandboxing directives during alpha (`ProtectSystem=strict`, `PrivateTmp=`, `ReadWritePaths=`). | Add Landlock / unveil / Capsicum file-descriptor confinement inside the process. |
| `core dump policy` | `RLIMIT_CORE` is not yet clamped from inside the process. | Call `setrlimit(RLIMIT_CORE, {0, 0})` at startup and disable `PR_SET_DUMPABLE`. |

## Operator expectations during alpha

- Deploy behind the supplied service-manager units (`packaging/systemd/`,
  `packaging/openrc/`, `packaging/rc.d/`). They apply the privilege-drop and
  filesystem confinement that the in-process code defers.
- Treat any `Hardening self-check: … =disabled` startup log as a defect and
  refuse to roll the release forward.
- Treat `Hardening self-check: … =alpha_exception` warnings as informational
  during alpha; production gating tests run the same self-check and refuse
  release when any exception remains.

## How to retire an exception

1. Implement the runtime control inside the process.
2. Replace the corresponding `alpha_exception` push in
   `src/platform/hardening_self_check.cpp` with a real probe that returns
   `enabled` or `disabled`.
3. Update the matching row in this document and remove it from the table when
   no longer deferred.
4. Update [`docs/01-progress-tracker.md`](01-progress-tracker.md) and
   [`CHANGELOG.md`](../CHANGELOG.md) to record the removal.
