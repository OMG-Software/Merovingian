# sync_max_in_flight bounds parked waits, not sync-pool threads

* Status: accepted; amends [ADR-0091](0091-bound-sync-waits-with-admission.md)
* Date: 2026-11-07

## Context and Problem Statement

[ADR-0091](0091-bound-sync-waits-with-admission.md) admitted at most `min(sync_max_in_flight, pool workers)`
waits globally, because every admitted wait held a sync-pool thread. A parked wait (ADR-0569) holds none, so the
clamp to the pool size would keep the concurrent long-poll count at the thread count and the parking would buy
nothing. What should the global cap be, and what bounds a pool queue the waits no longer fill?

## Considered Options

1. Keep the clamp. Rejected: defeats ADR-0569.
2. A new key for the parked cap. Rejected: `sync_max_in_flight` already is "how many waits the server admits"; a
   second number that must be kept in step with it is a way to misconfigure.
3. Reuse `sync_max_in_flight` as the cap on every admitted wait, parked, queued or running, and raise its default
   and ceiling (chosen).

## Decision Outcome

`sync_admission_caps` takes the global cap from `server.http.sync_max_in_flight` alone when a sync pool exists;
only the no-pool fallback (a wait holds the calling thread) is still clamped to the configured `sync_threads`.
The per-account and per-device caps stay below it. The sync pool's queue depth is `sync_max_in_flight`, so an
admitted wait can always be queued: admitted waits never exceed the depth, and a task that is queued or running
holds one admission slot. `sync_max_in_flight` defaults to 2048 (was 128) and its range is 1..16384 (was 1..512);
the registry caps parked entries at the same value, and `sync_max_per_user` per user.

The memory a parked wait holds is its connection, its copied request and its slots, a few KiB; the descriptor is
already bounded at accept time by `listeners` and `server.http.max_connections_per_ip`. Raising the key is a
restart-required change, as before.

## Links

* [ADR-0569](0569-a-long-poll-with-nothing-to-return-parks-in-a-registry-and-gives-up-its-sync-pool-thread.md),
  [ADR-0091](0091-bound-sync-waits-with-admission.md).
