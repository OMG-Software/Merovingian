# The integration binary runs as four Catch2 shards with one fixed seed

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

`meson test` ran `merovingian-integration-tests` as one test: 806 seconds on Ubuntu and 748 on NetBSD, while every other test
took under 135. The suite's wall time was that one serial process, on runners with four vCPUs. Catch2 3.16.1 can run a slice of
a binary with `--shard-count` and `--shard-index`.

## Considered Options

* Keep one test.
* Split the integration sources into several binaries.
* Register Catch2 shards of the one binary as separate Meson tests.

## Decision Outcome

Chosen: Catch2 shards. `tests/meson.build` registers `integration-tests-shard-N-of-4`, which Meson runs in parallel. Each runs
`~[postgresql]~[serial]` with `--order rand --rng-seed 271828`. Two more tests run what the shards leave out:
`integration-tests-postgresql` runs `[postgresql]` in one process, and `integration-tests-serial` runs `[serial]` with
`is_parallel: false`. `integration-shard-coverage` (`scripts/check-integration-shards.sh`) lists what each shard and filter
selects, and fails unless together they run every scenario exactly once.

Every shard must get the same `--order` and a numeric `--rng-seed`. Catch2 shuffles with a seed chosen per process and gives
each shard a contiguous slice of its own order, so shards with different seeds overlap and leave scenarios out without
reporting it. The fixed seed also spreads the slow source files across shards.

`[postgresql]` scenarios share the one database `MEROVINGIAN_TEST_POSTGRESQL_URI` names, so they never run in two processes at
once. `[serial]` marks a scenario that probes a free port and closes it before a spawned server binds it, a window in which
another process's socket can take the port. A new integration scenario that does either must carry the tag.

Rejected:

* **One test.** The suite waited for the longest binary while three cores idled.
* **Separate binaries.** Each would link the whole server again, and the split would have to be rebalanced by hand as files
  grow.

## Consequences

* The integration scenarios now share the machine with other tests at once. A timing-sensitive scenario that flakes under that
  load is a bug in the scenario, or a `[serial]` tag it is missing.
* Every run uses the same scenario order, so random ordering no longer varies between runs.
* `meson test integration-tests` matches nothing; name a shard, `integration-tests-postgresql` or `integration-tests-serial`.
* Each test keeps the whole binary's timeout as a hang detector.
