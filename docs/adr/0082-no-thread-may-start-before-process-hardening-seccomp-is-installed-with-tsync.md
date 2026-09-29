# No thread may start before process hardening; seccomp filters are installed with TSYNC

* Status: accepted
* Date: 2026-09-29

Technical Story: finding ISO-1 in `docs/security-audit-report-2026-09-29.md`
(Area 8, process isolation and platform hardening).

## Context and Problem Statement

A seccomp filter and a Landlock ruleset both attach to the calling thread. A
thread that already exists when either is installed keeps whatever it had. The
logger's constructor started two writer threads, and the federation worker's
first `LOG_INFO` constructed the logger before Landlock and the worker seccomp
filter were applied. Those two threads kept only the filter inherited from the
main process, which allows `execve`, `open`, `socket` and `connect`, and had no
Landlock ruleset. A compromised worker thread could install a signal handler
(`rt_sigaction` is allowed) and aim it at a logger thread with `tgkill` (also
allowed); the handler then ran unconfined and could read the master key or
`execve` a shell. The self-check read `/proc/self/status`, which describes only
the thread-group leader, so it could not see this. The worker's whole
containment (ADR-0015, ADR-0062, issue #319) was bypassable with syscalls its
own allowlist permits.

The constraint is not visible where the code that breaks it is written. The
logger, a thread pool, a library that spawns a helper thread, or a "harmless"
early log line can each create a thread far from `main()`, and nothing in the
type system or the tests said that creating it there was wrong.

## Considered Options

* Move the worker's first log line after hardening and leave the rest as it is.
* Install the filters and Landlock in the logger's writer threads as well.
* Install seccomp with `SECCOMP_FILTER_FLAG_TSYNC` only.
* Start no thread before hardening (the logger writes synchronously until told
  to start its writers), install seccomp with `TSYNC`, and make the self-check
  read every task.

## Decision Outcome

Chosen option: the last one, as three rules that together are the decision.

1. **No thread may start before a process's Landlock ruleset and seccomp
   filter are installed.** `observability::SingleLog` therefore starts no
   thread in its constructor. Until `start_writers()` is called it writes each
   line synchronously under a mutex, so an early message is neither lost nor
   able to deadlock. Executables call `start_writers()` after hardening
   (`merovingian-fed-worker`, and `merovingian-server` after its seccomp filter
   and runtime controls). A short-lived tool that never calls it still logs
   correctly. Any future code that starts a thread must run after hardening in
   every process that hardens itself.
2. **Every seccomp filter is installed with `seccomp(SECCOMP_SET_MODE_FILTER,
   SECCOMP_FILTER_FLAG_TSYNC, ...)`,** not `prctl` and not with flags 0. It
   confines any thread that already exists, as defence in depth for rule 1, and
   a failure (including the kernel reporting a thread it could not synchronise)
   is fatal, with no fallback to a per-thread install.
3. **The hardening self-check reads `/proc/self/task/<tid>/status` for every
   task** and requires `Seccomp: 2` and `NoNewPrivs: 1` in all of them. A task
   that cannot be read or parsed counts as unconfined.

Rule 1 matters most for Landlock. The Landlock restriction call has no
thread-sync flag on the kernels this project supports, so ordering is the only
thing that confines a thread against it. `TSYNC` therefore does not make rule 1
optional, and a pre-existing thread is confined by seccomp but not by Landlock.

### Positive Consequences

* Every thread the worker ever runs, including the logger's, carries the
  Landlock ruleset and the worker seccomp filter.
* An unconfined sibling thread is now a start-up failure in the self-check
  rather than an invisible state.
* Short-lived tools (`--check-config`, `--dry-run`, `db-migrate`) create no
  logger threads at all.

### Negative Consequences

* Until `start_writers()` runs, each log call takes a mutex and writes to
  stdout (and the log file) on the calling thread. That is bounded and only
  covers start-up.
* A sanitizer runtime that starts its own helper thread would now have that
  thread filtered too. GCC's ASan runtime starts none by default (checked: the
  process has one task after allocating), but a future runtime that does would
  need its syscalls added to the allowlists.
* The worker does not assert "exactly one task" before Landlock, because a
  sanitizer runtime's own thread would make every sanitizer build refuse to
  start. The ordering is enforced by convention, the tests, and the self-check.

## Pros and Cons of the Options

### Move the worker's first log line after hardening

* Good, because it is a one-line change.
* Bad, because the next early log line, or any other early thread, reopens the
  hole silently. It fixes the instance and not the rule.

### Install the filters and Landlock in the writer threads as well

* Bad, because it makes every thread creator responsible for hardening itself
  and gives Landlock no way to be applied consistently.

### `TSYNC` only

* Good, because it also covers a thread we forgot about.
* Bad, because it does nothing for Landlock, which has no thread-sync flag on
  older kernels.

### Start no thread before hardening, plus `TSYNC`, plus per-task self-check

* Good, because each control covers a different failure: ordering covers
  Landlock, `TSYNC` covers seccomp if the ordering is broken, and the
  self-check turns either mistake into a refusal to start.
* Bad, because the logger has two modes.

## Links

* Related to [ADR-0053](0053-the-thumbnail-decoder-gets-its-own-syscall-profile.md)
* Related to [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
* Related to [ADR-0041](0041-refuse-to-start-the-federation-worker-unsandboxed.md)
