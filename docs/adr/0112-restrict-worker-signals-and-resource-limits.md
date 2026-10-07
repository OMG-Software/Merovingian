# Restrict worker signals and resource limits

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-05

## Context and Problem Statement

The federation worker's seccomp filter allowed `kill`, `tgkill`, `tkill`,
`setrlimit`, and `prlimit64` without argument filtering. A compromised worker
could terminate, freeze, or relax the resource limits of the main process or
other processes on the host (security audit finding ISO-2). Landlock was also
not requesting ABI-6 signal scoping, so a compromised worker could send signals
to processes outside its sandbox.

## Decision Drivers

* A worker must not be able to affect processes outside its own thread group.
* The worker legitimately needs `tgkill` for internal thread signalling (e.g.
  `pthread_cancel`), but only when targeting itself.
* Landlock should use the latest available ABI features to narrow the signal
  target surface.

## Considered Options

1. **Block all signal-related syscalls.** Rejected: glibc's thread cancellation
   path uses `tgkill` to deliver cancellation signals between worker threads.
2. **Allow `tgkill` for any tgid.** Rejected: that preserves the original
   finding — a compromised worker could signal the main process if it knows the
   TGID.
3. **Allow `tgkill` only when `args[0]` equals the worker's own TGID, remove
   `kill`/`tkill`/`setrlimit`/`prlimit64`, and request `LANDLOCK_SCOPE_SIGNAL`
   on ABI 6.** Accepted: it keeps the worker self-contained while still allowing
   internal thread signalling.

## Decision Outcome

Chosen option: "argument-filter `tgkill` to the worker's own TGID, remove the
other process-control syscalls from the worker allow-list, and enable Landlock
ABI-6 signal scoping", because it closes the escape surface without breaking the
thread runtime the worker relies on.

### Positive Consequences

* A compromised worker cannot send signals to arbitrary processes or change its
  own resource limits.
* Landlock signal scoping prevents the worker from signalling processes outside
  its sandbox on modern kernels.

### Argument checks in the generated BPF program

`build_seccomp_program` emits one `JEQ nr` / `RET ALLOW` pair per allowed
syscall, with the syscall number in the accumulator throughout. An entry that
checks an argument breaks both assumptions, so it must:

* jump over exactly its own instructions when the syscall number does not match,
  so the next entry starts at its own `JEQ`; and
* end in its own `RET` of the default action when the argument does not match,
  because loading the argument overwrote the accumulator and the entries after it
  would otherwise compare that argument against syscall numbers.

The first implementation of this ADR got the first rule wrong by one instruction:
a non-`tgkill` syscall landed on the next entry's `RET ALLOW`, so every syscall
not matched earlier in the list, `kill`, `prlimit64` and `execve` included,
was allowed. Its tests only checked list membership, and the one real-kernel test
that failed was skipped as a kernel quirk. A test of an argument-filtered entry
must therefore install the real filter in a forked child and make the calls
(`[iso2]` in `tests/unit/test_worker_hardening_threads.cpp`); a membership
check cannot see a jump-offset error.

### Negative Consequences

* Kernels older than Landlock ABI 6 do not get signal scoping; the seccomp
  restriction still applies on all supported Linux kernels.
* The worker still runs under the same uid as the main process, which the audit
  preferred. The seccomp argument check is what stops it signalling main, so it
  must not be relaxed while that is true.

## Links

* Security audit finding ISO-2 in `docs/security-audit-report-2026-09-29.md`.
* Related hardening rules in `docs/hardening.md`.
