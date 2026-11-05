# The integration test limit is thirty minutes on every platform

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-05

Technical Story: PR #560 CI

## Context and Problem Statement

`integration-tests` had a 900 s limit. On main it already took 877 s in the PostgreSQL job, and the scenarios of 0.12.76
add about 62 s, so Linux jobs started to time out at different tests with no assertion failing. The BSD jobs did not,
because `scripts/build-bsd.sh` runs `meson test` with `--timeout-multiplier 2` by default, which gave them 1800 s.

## Considered Options

* Raise the limit to 30 minutes on every platform
* Keep 900 s and remove the waits that make the suite slow
* Set `timeout: 1800` everywhere and leave the BSD multiplier to double it

## Decision Outcome

Chosen option: "Raise the limit to 30 minutes on every platform", by the owner's decision.

`tests/meson.build` sets 1800 s, and 900 s on FreeBSD, NetBSD and OpenBSD, where the driver's default multiplier brings
it to 1800 s. A change to that multiplier has to change this value with it; `tests/tooling/test_dependency_wraps.py` holds
the two together. The BSD multiplier stays because OpenBSD's unit and conformance binaries need it (641 s of 600 s and
1033 s of 900 s before the multiplier).

### Consequences

* A hang in this binary takes up to 30 minutes to be reported on a plain run, not 15.
* An explicit multiplier still scales the limit: the coverage build (2) gets 60 minutes and the sanitizer jobs (3) get
  90 minutes on Linux. Those are build configurations with their own slowdown, not platforms.
* Running `meson test` directly on a BSD host, without the driver, gets 900 s.
* The time the suite spends waiting is not reduced by this. `fix/integration-tests-time-budget` works on that separately,
  and describes the limit as unchanged, so it needs reconciling with this record when it lands.

### Rejected

Doubling on the BSDs: 60 minutes there is not what was asked for, and it would slow hang detection on the jobs that
already passed.
