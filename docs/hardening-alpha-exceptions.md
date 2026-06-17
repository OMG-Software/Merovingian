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
| `pledge/unveil` | OpenBSD pledge/unveil are scaffolded but not invoked at startup. | Call `pledge("stdio rpath wpath cpath inet …", NULL)` and `unveil` per documented surface. |
| `capsicum` | FreeBSD Capsicum capability mode entry is not yet wired into startup. | Call `cap_enter()` after listeners bind and before request handling. |
| `privilege drop` | Privilege drop is delegated to the service manager (systemd `User=`, OpenRC `user=`, rc.d `_user`) during alpha. | Add an in-process `setresgid`/`setresuid` step gated by configuration. |
| `filesystem restrictions` | Filesystem confinement is delegated to systemd sandboxing directives during alpha (`ProtectSystem=strict`, `PrivateTmp=`, `ReadWritePaths=`). | Add Landlock / unveil / Capsicum file-descriptor confinement inside the process. |

## Retired exceptions

| Check | Retired in | What replaced it |
| --- | --- | --- |
| `linker hardening` | v0.7.2 | ELF program-header probe via `/proc/self/exe` (Linux). Reports `enabled` when `PT_GNU_RELRO`, `DT_BIND_NOW`, and `PT_GNU_STACK` (noexec) are all present; `unknown` otherwise (static or dev build). |
| `RELRO` | v0.7.2 | Same ELF probe as `linker hardening`. Reports `enabled` when `PT_GNU_RELRO` is present; `unknown` otherwise. |
| `seccomp` | v0.7.2 | Runtime BPF syscall allowlist applied via `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SECCOMP_SET_MODE_FILTER)` before listeners bind. Reports `enabled` when `/proc/self/status` confirms `Seccomp: 2`; `unknown` on non-Linux, old kernels, or dev/dry-run invocations. Default action is `SECCOMP_RET_LOG` for beta. |
| `core dump policy` | v0.8.18 | `setrlimit(RLIMIT_CORE, {0, 0})` + `prctl(PR_SET_DUMPABLE, 0)` applied on Linux at startup; self-check probes via `getrlimit`. |
| `no_new_privs` | v0.8.18 | `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` applied on Linux at startup; self-check probes via `PR_GET_NO_NEW_PRIVS`. |
| `capability bounding` | v0.8.18 | Linux capability bounding set is dropped with `prctl(PR_CAPBSET_DROP, ...)` for every capability before listeners bind. |

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
4. Update [`docs/todos/capability-gaps.md`](todos/capability-gaps.md) and
   [`CHANGELOG.md`](../CHANGELOG.md) to record the removal.
