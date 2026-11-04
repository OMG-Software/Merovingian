# The event table keeps a per-room index in stream order, and a request reads its room through it

* Status: accepted
* Date: 2026-11-04

Technical Story: performance defects P2 and P3 of the 2026-11-04 project analysis (`/sync` is O(rooms x events))

## Context and Problem Statement

`/sync` built each joined room's timeline with `for (event : store.events)` filtered by `room_id`, so a sync of R rooms
walked R times every event the server holds, under `runtime.mutex`. The same walk sat under `/messages`, `/context`,
`/search`, `initialSync`, `/relations`, `read_markers_for`, `count_unread_by_thread`, the sliding sync timeline and
timestamp, and `state_anchor_event`. `EventTable` already had a per-room index (ADR-0300), but it is keyed by
`origin_server_ts` and holds timeline events only, while these readers select by stream ordering and, by the rules
in ADR-0215 and ADR-0289, must see rows of every status (a backfilled event is ordered after the join it precedes, an
outlier carries a state group, rejected rows are judged by the reader).

How does a request read one room's rows in stream order without visiting the others?

## Considered Options

1. Reuse the time index (`by_room_time_`) and sort by stream ordering per request.
2. Keep a per-room index of positions in `rows_`, ordered like the global stream order, over rows of every status.
3. Store a counter per room (unread counts) so no walk is needed.

## Decision Outcome

Chosen option 2: `EventTable::room_in_stream_order(room_id)` visits exactly the rows `in_stream_order()` visits whose
`room_id` matches, in the same order (equal stream orderings in the order added). `insert`, `insert_all`, `erase_if`,
`modify` (a mutation that changes `room_id`) and `clear` keep it current; no caller maintains it.

Option 1 fails because that index drops outliers, rejected and soft-failed rows and rows without an integer
`origin_server_ts`, which the readers either need or filter themselves; it is also ordered by time, and ADR-0289 depends on
stream order. Option 3 was refused for this change (no stored counters, ADR-0207).

A reader that needs a room's rows uses this index. Do not write `for (x : store.events)` plus a `room_id` test on a request
path. A walk of the whole table stays only where it needs every room (start-up, `rebuild_redaction_state`, the classifier's
single per-request pass over join transitions, ADR-0207).

### Consequences

* The per-room walks cost the room's rows. A reader that stops early may walk the view in reverse.
* A reader must not rely on the order of rows sharing a stream ordering other than "added first, first" (the old code sorted
  with an unstable sort, so it did not either).
* `state_anchor_event` walks newest first and keeps the earliest-added of the rows sharing the highest eligible ordering,
  as comparing every row did.
* The `event_json_is_state_event` parse is evaluated only when the sender is on the viewer's ignore list
  (`withheld_as_ignored`).
