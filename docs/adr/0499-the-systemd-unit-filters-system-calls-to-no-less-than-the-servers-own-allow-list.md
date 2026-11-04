# The systemd unit filters system calls to no less than the server's own allow-list

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`packaging/systemd/merovingian.service` had no `SystemCallFilter`, no file-descriptor or task ceiling, no
`ProtectProc` and no stop timeout. The server, the federation worker and the thumbnail worker already install their
own seccomp filters (`src/platform/seccomp_hardening.cpp`, a kill-on-violation allow-list), and the memory of an
earlier change that made seccomp allow-all means a filter change must be tried on a real kernel. What filter may the
unit carry without breaking those installations?

## Considered Options

* `SystemCallFilter=@system-service` alone.
* `@system-service` with `~@privileged @resources`.
* `@system-service` plus every system call the processes' own filters allow and install themselves with.

## Decision Outcome

Chosen option: the third. A systemd filter is only safe if it is a superset of what the processes need, and the
processes' own allow-lists are the authoritative statement of that.

* `@system-service` alone was tried under a transient user unit with the real server: it was killed with SIGSYS before
  its self-check, because `seccomp` and `landlock_*` are outside the group (systemd 254 added them to `@sandbox`, which
  older systemd does not know). `~@privileged @resources` would remove `setrlimit`, `capset` and friends that the
  hardening itself calls.
* The unit lists every `__NR_` name in `seccomp_hardening.cpp` plus the install-time calls.
  `tests/tooling/test_systemd_unit.py` fails when the cpp gains a call the unit lacks, so the two cannot drift. A name
  the running systemd does not know is ignored with a warning.
* `SystemCallErrorNumber=EPERM`: a call outside the list fails, instead of killing the process. A failed `seccomp()`
  then makes start-up refuse, which is visible, rather than a silent partial outage.
* `TimeoutStopSec=300s` exceeds the longest graceful stop: the worker supervisor waits `request_timeout_seconds`
  (default 120 s) for a worker to exit, sends SIGTERM and waits another 120 s before SIGKILL, so 240 s. In-flight
  outbound calls end within their own 30 s defaults. An operator who raises `request_timeout_seconds` must raise it.
* `LimitNOFILE=65536` and `TasksMax=4096` are ceilings above the default thread pools (a few hundred tasks across the
  server and workers), not tuned numbers; raising the `*_threads` settings needs `TasksMax` raised with them.
* `WatchdogSec` is deliberately absent: the server never calls `sd_notify`, so a watchdog would kill a healthy
  server. Adding the call is a separate change.
* OpenRC gets `rc_ulimit` and `retry` with the same numbers. BSD `rc.d` has no per-service equivalent here (login
  classes) and is unchanged.

## Consequences

* The filter was exercised on a real kernel only for start-up, both seccomp installations and a clean worker stop,
  using `scripts/check-startup-hardening-gate.sh` under `systemd-run --user`. Request handling, PostgreSQL, TLS and the
  thumbnailer were not run under the unit filter; they are covered by the processes' own allow-list being a subset.
