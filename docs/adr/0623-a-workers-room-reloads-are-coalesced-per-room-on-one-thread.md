# A worker's room reloads are coalesced per room, on one thread

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, resource-exhaustion.federation-worker-room-sync.uncoalesced-full-room-reload-per-accepted-pdu

## Context and Problem Statement

Main sends a worker a `room_sync` for every event it accepts, and the worker answered each with a full re-read of the
room. A remote server sending PDUs to one large room therefore chose how many whole-room reads a shard did, and each
one parked a `local_pool` thread on the reload mutex, starving the local endpoints that pool serves.

## Considered Options

* Drop a notification if a reload of the room is already queued
* Debounce by time
* Coalesce per room with a dirty flag, on a thread of their own

## Decision Outcome

Chosen option: `RoomReloadCoalescer`, with reloads on a one-thread `reload_pool`.

* A room is scheduled at most once. A notification for a scheduled room only marks it dirty and records the newest
  generation. A round clears dirty, reloads, then looks again: dirty means another round.
* **The invariant: a reload that starts after a notification was recorded sees the change it announces**, because main
  commits before it notifies and the round reads after clearing dirty. So the last notification of a burst is always
  followed by a round whose read began after it, and a burst of any length arriving during one round costs one more.
* Dropping a notification when a reload is merely queued is only safe if the reload has not started, which the worker
  cannot tell without this state. A debounce adds latency to every event and still needs the same flag.
* The coalescer's mutex covers its table only: no lock is held across the database read
  ([ADR-0360](0360-the-worker-guards-its-store-with-a-reader-writer-lock-taken-only-for-the-swap.md)).
* Each round reports `room_sync_result` with the newest generation it covered. `WorkerPool` marks a room's status only
  for the latest generation it sent, so a failed round followed by a good one ends good, and a generation
  that is never reported is impossible as long as the round runs.
* A separate pool of one thread, because reloads serialise on the guard anyway: on `local_pool` they only parked threads
  that local requests needed. Rounds of different rooms take turns on it, so one busy room cannot hold it for long.

### Negative Consequences

* `apply_room_snapshot` is still a whole-store swap under the reload mutex (ADR-0360), so one reload's cost is not
  reduced. The number of reloads is what is now bounded: at most one running and one following, per room.

## Links

* Refines [ADR-0360](0360-the-worker-guards-its-store-with-a-reader-writer-lock-taken-only-for-the-swap.md)
