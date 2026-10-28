# No sync position passes a stream ordering still being committed

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-28

Technical Story: Complement `TestRestrictedRoomsRemoteJoin` and its relatives, where a local user's
`/sync` never showed a remote user's leave that this server had stored.

## Context and Problem Statement

Inbound PDU ingestion reserves an event's stream ordering, then releases `runtime.mutex` for the
backend commit, so independent rooms commit concurrently, and only afterwards applies the event to
the in-memory store. `/sync`, sliding sync and the long-poll check took "now" as
`next_stream_ordering - 1`, which counts reservations. A sync in that window handed out a token
naming the reserved ordering; the event was applied a moment later, at or below every later
`since`, and no timeline ever carried it. In the Complement log a sync returned ordering 22 four
milliseconds before the leave with ordering 22 was applied.

The main ingest path also reserved its ordering early, before taking the room stripe, before
missing-history fetches over the network, so a reservation could stay open for as long as such a
fetch took.

## Decision Drivers

* A token must never pass an event the client has not been given.
* One slow room must not hold back every other user's sync.
* The commit stays outside `runtime.mutex`.

## Considered Options

* Track reserved-but-unapplied orderings (`PendingStreamOrdering`, an RAII guard over
  `LocalDatabase::pending_stream_orderings`), and give out `visible_stream_position`: just below the
  oldest pending one. Reserve the main ingest path's ordering where the event takes it, after any
  missing-history fetch, so a reservation spans only the commit.
* The same guard, with the reservation left up front.
* Commit with `runtime.mutex` held.

## Decision Outcome

Chosen option: the guard, with the reservation moved next to the commit. Every path that commits
with the mutex released holds a guard from the allocation until the event is applied; both today
are in `local_http_router.cpp` (main ingestion and the verified backfill writer).

Left up front, a reservation stayed pending across network fetches, and the guard would then have
held every user's sync position back for as long as one room's history took to fetch. Committing
under the mutex serialises every room's database writes behind it, which the unlocked commit
exists to avoid.

### Positive Consequences

* A sync token never skips an event that is still being committed.
* The hold lasts one commit.

### Negative Consequences

* The main path's watermark write in `allocate_stream_ordering` now runs with the room stripe held,
  next to the event's own commit.
* A new path that commits with the mutex released and forgets the guard brings the bug back;
  `PendingStreamOrdering`'s comment and this record say so.
