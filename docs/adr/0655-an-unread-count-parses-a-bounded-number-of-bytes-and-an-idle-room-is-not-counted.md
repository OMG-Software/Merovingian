# An unread count parses a bounded number of bytes, and a room that is not sent is not counted

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C05 (unread counts parse up to a thousand sender-sized events per joined room on every sync).

## Context and Problem Statement

ADR-0617 bounded an unread count to the newest 1,000 rows above the read marker. An event is up to 64 KiB and may hold
tens of thousands of JSON values, and each counted row was parsed in full, classified against the user's push rules and
followed through up to three parents, each parsed in full. A member who posts 1,000 large events makes every member who
has not read past them pay about 1,000 x 4 x 64 KiB of parsing per joined room on every `/sync`, idle ones included, under
the runtime lock. The floor of the walk is the read marker, not `since`, so an idle incremental sync repeated it.

## Decision Drivers

* The work of one count is bounded by a constant independent of event size.
* Counts the client sees stay exact whenever they are not capped, and the cap is the same kind as ADR-0617's row cap: a
  lower bound.
* An incremental sync does not count a room it is not going to send.

## Considered Options

* A byte budget for the JSON one count parses (events and parents), `max_unread_bytes_parsed` = 512 KiB, and the
  incremental sync's "nothing new" check moved before the count.
* Store a parsed or pre-classified form of each event at write time.
* Reuse the client's last counts on an incremental sync.

## Decision Outcome

Chosen option: the first.

* `count_unread_by_thread` spends each classified event's JSON size from the budget and stops, as at the row budget, when
  the next one does not fit. `event_thread_id` takes an optional budget and spends each parent it parses from it; a
  parent that no longer fits ends the search in the main timeline, as a parent the server does not hold does. Rows skipped
  before parsing (not accepted, the user's own, not visible) cost nothing. 512 KiB holds about 8 events of the largest size
  and about 500 of 1 KiB; ordinary events (a few hundred bytes) never reach it, so their counts are exact.
* The capping rule: when the byte or the row budget ends a count, the newest events up to that point are counted and
  nothing older is, so a count never exceeds the true count and never counts an event `/sync` would not show.
* In `sync_json` the check that drops a joined room with nothing new on an incremental sync now runs before the unread
  counts, which such a room never shows. Counts are unchanged for every room that is sent.

### Negative Consequences

* A reader behind a run of very large notifying events sees a lower count than the true one, until they read.
* The push badge count (`count_push_badge`) has its own row budget and is not given this byte budget here; it is the
  subject of finding C15.

## Links

* Builds on ADR-0617 and ADR-0616.
