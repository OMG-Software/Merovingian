# The recency and name sort keys are read per room through the indexes

* Status: Accepted
* Date: 2026-11-12

Technical Story: security audit run 3, finding C07 follow-up

## Context and Problem Statement

ADR-0665 moved the list filters and the notification sort onto the request's lookups but left two sort keys as they were:
`by_recency` with `bump_event_types` walked the whole event table once per list, and `by_name` made one pass over the whole
state table and one over the event table per list. Under `runtime.mutex` those cost the events and state of every room
on the server, which a low-trust account grows by sending.

## Considered Options

* Read both per joined room through the room indexes, in `SlidingSyncRequestLookups`, with a fixed row budget per room.
* Read recency with `EventTable::walk_room_newest_first`.
* Keep one pass per list and cache the result per request.

## Decision Outcome

Chosen option: "per joined room through the room indexes".

* `by_name` reads the room's current `m.room.name` through `find_current_state_event_id` and the event by ID, once per
  room per request. The key is the same `content.name` as before (an unnamed room sorts last); it does not read the
  canonical alias or heroes, which the sort never used.
* `by_recency` reads the room's own rows newest first (`room_in_stream_order`, ADR-0435) and takes the first whose
  `type` is in `bump_event_types`; with no bump types it is the room's newest row. This is the same value as before: the
  greatest stream ordering among the room's events of those types, of every status.
* At most `max_recency_rows_examined` (1000) rows are read per room. When none matched in that many, the room's newest
  event's ordering stands in (the key the room would have with no bump types), so the sort stays total and cheap; a
  room whose last 1000 events are all of other types may then sort higher than an exact answer, never lower than its
  newest event warrants. The answer is memoised per room and set of bump types, so lists sharing them share the work.

### Rejected: `EventTable::walk_room_newest_first`

It orders by origin timestamp, depth and stream ordering, and offers timeline events only. The sort key is the stream
ordering of the newest matching event, of any kind, so that walk can return a different room order than the old key.

### Rejected: one pass per list, cached per request

It still costs every room's events once per request, which is the finding.

## Consequences

* A request's sort cost is the user's joined rooms times at most 1000 rows, however many events and state rows other
  rooms hold. `recency_rows_visited()` is what the tests read.
* In the rare room whose newest 1000 events are all of other types, `by_recency` with bump types uses the newest event.
