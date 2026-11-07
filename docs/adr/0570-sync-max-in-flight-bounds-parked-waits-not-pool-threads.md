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
holds one admission slot. `sync_max_in_flight` defaults to 512 (was 128) and its range is 1..16384 (was 1..512);
the registry caps parked entries at the same value, and `sync_max_per_user` per user.

The memory a parked wait holds is its connection, its copied request and its slots, a few KiB. Its socket is
a file descriptor the whole time, and `server.http.max_connections_per_ip` bounds that per client address only,
not in total. The default is therefore 512, not higher: with 256 idle keep-alive connections, the request
threads and the database and outbound sockets, the process stays under the 1024 open files many hosts give a
daemon by default (the BSD rc scripts set no limit of their own). Past the limit `accept4` fails with `EMFILE`
and the listener retries every 100 ms, so new clients stall. An operator raising the key must raise the
descriptor limit with it; the systemd unit's `LimitNOFILE=65536` (ADR-0499) leaves room for the maximum.
Rejected: a 2048 default, which exceeds a 1024 descriptor limit before any other connection is counted.
Raising the key is a restart-required change, as before.

## Links

* [ADR-0569](0569-a-long-poll-with-nothing-to-return-parks-in-a-registry-and-gives-up-its-sync-pool-thread.md),
  [ADR-0091](0091-bound-sync-waits-with-admission.md).
