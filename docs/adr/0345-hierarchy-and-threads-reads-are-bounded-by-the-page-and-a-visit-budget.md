# Hierarchy and threads reads are bounded by the page and by a budget of rooms or rows

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-32 (`GET /hierarchy`) and F-33 (`GET /threads`)

## Context and Problem Statement

Both endpoints applied their page `limit` after building the whole answer, under `runtime.mutex`. `GET /hierarchy`
walked the entire space tree for every page, and `GET /threads` parsed every event the server stores, twice, looking each
thread root up in a vector. The spec tells servers to "impose a maximum value to avoid resource exhaustion" on the
`limit`; it does not say how much of the tree or room a request may read.

## Decision Drivers

* Work under `runtime.mutex` must not grow with the size of data a client or remote server controls (a space's links, a
  room's events).
* Pagination must stay spec-conformant: `from` tokens work, and a token whose `max_depth` or `suggested_only` differs
  is answered 400 `M_INVALID_PARAM`.

## Decision Outcome

### `/hierarchy`

* `walk_hierarchy_client` stops once it holds `offset + limit + 1` rooms (the extra room tells it a `next_batch` is due)
  or has looked at `max_hierarchy_walk_visits` (4096) rooms, listed or not. The token still carries only the offset; each
  page walks from the root again, but only as far as its own end, depth-first as before.
* A tree larger than the visit budget lists its first 4096 rooms. A token's offset above the budget lists nothing.
  There is no `next_batch` for rooms the walk did not reach; the spec has no way to say so.
* `SpaceHierarchyResult::rooms_visited` reports the count, for tests.

### `/threads`

* The aggregation is keyed by root ID in a hash map and walks only the room's events through `EventTable`'s per-room
  time index (`walk_room_newest_first`, newest first), offering at most `max_thread_events_examined` (10000, the default
  of `max_search_events_scanned`) of them. Each root is then found by an ID lookup, not a second walk.
* A relation whose `event_id` is not a well-formed event ID (appendices: `$` and the ID characters, at most 255 bytes)
  is ignored. Stored federated events are not refused; they are skipped when read.
* The room-time index holds timeline events only (not outliers, rejected or soft-failed events, and not rows with no
  integer `origin_server_ts`), so those no longer count towards a thread.
* In a room with more events than the budget, a thread whose children are all older than the newest 10000 events is
  not listed, and the `count` of one with older children is of the children examined. The spec offers no way to flag
  this. It was chosen over resuming a scan from a cursor, because a `next_batch` that continues below the budget would
  list a thread again by its older child while its newer child is already on the first page.
* The budget is a constant, not a config key: nothing needs to tune it yet.

### Negative Consequences

* A very large space or a very busy room is answered from its first rooms or newest events only.
* `GET /hierarchy` still re-walks from the root for each page, bounded by the page's end.
