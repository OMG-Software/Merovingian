# The decoder seccomp children skip under ThreadSanitizer instead of widening its allowlist

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

`test_seccomp_hardening.cpp` proves the thumbnail decoder's seccomp filter on the real kernel: a forked child installs
it with `SECCOMP_RET_KILL_PROCESS` and makes one call, and the scenario requires the child to survive an allowed call
and die by `SIGSYS` on a refused one (ADR-0642). The `tsan` job failed one of these: a child that made only
`fcntl(F_SETFL, O_NONBLOCK)`, which the filter allows, was killed by `SIGSYS`.

ThreadSanitizer starts its background thread again in a forked child (the reason the task-count scenarios already skip
under it), and every filter is installed with `SECCOMP_FILTER_FLAG_TSYNC` (ADR-0082), so the decoder filter covers that
thread too. The thread sleeps with `nanosleep`, which the decoder allowlist does not hold: the decoder is
single-threaded in production. When the runner schedules that thread only after the filter is in place, seccomp kills
the child whatever the child itself called. The outcome depends on scheduling, so it fails rarely.

How should the decoder's filter be tested under ThreadSanitizer?

## Considered Options

* Skip the decoder's forked children under ThreadSanitizer
* Allow `nanosleep` and `clock_nanosleep` in the decoder filter in ThreadSanitizer builds, as `personality` is (#428)
* Keep the children and retry a killed one

## Decision Outcome

Chosen option: "Skip the decoder's forked children under ThreadSanitizer", because the other jobs run the same children
on the same filter and kernel, and nothing about the filter changes to suit a test.

Each section that forks decoder children calls `skip_decoder_children_under_tsan` as a statement at its top: the decoder
`WHEN` of the signal-command and terminal scenarios, and the `GIVEN` of the decoder stat scenario. Never call it from a
helper an assertion calls, such as `child_survives`: Catch2 reports a `SKIP` thrown inside a `REQUIRE` expression as an
unexpected exception, so every check fails instead of skipping. The three scenarios are in the `tsan` group of
`tests/expected_skips.json`. Their worker and no-filter children still run under TSan: the worker allowlist holds both
sleeps. The `sqlite-mode` and `umask` scenarios keep their decoder children, because those expect a kill, which a kill
by the background thread cannot turn into a pass of a refused call.

### Positive Consequences

* The `tsan` job no longer fails on a scheduling accident, and the decoder filter stays exactly what production runs.

### Negative Consequences

* Under ThreadSanitizer the decoder's allowed and refused commands are not proved; the release, ASan and UBSan jobs
  prove them.

## Pros and Cons of the Options

### Allow the sleeps in ThreadSanitizer builds

* Good, because the children would run under TSan too.
* Bad, because it makes the filter under test differ from production's, for a call no decoder makes, and the background
  thread may make other calls the allowlist refuses; each would need adding in turn.

### Retry a killed child

* Bad, because a retry cannot tell a background-thread kill from the filter refusing an allowed call, which is the
  defect these children exist to catch.

## Links

* Related [ADR-0642](0642-seccomp-refuses-the-fcntl-and-ioctl-commands-that-arrange-signal-delivery.md)
* Related [ADR-0082](0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md)
* Related [ADR-0546](0546-ci-fails-on-a-catch2-skip-its-job-does-not-list.md)
