# A sync serves the joined rooms that can have news, and the most recently active when there are too many

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C34, review of the first version (ADR-0654).

## Context and Problem Statement

ADR-0654 counted every joined room that passed the room filter against `max_sync_rooms` before doing its work, in the
order of `database.rooms`. On an incremental sync most rooms have nothing new, so a user joined to more rooms than the
cap spent the whole cap on idle rooms and never heard from a room past it. The loop also began with a walk of every room
on the server, asking each whether the user had joined it.

## Decision Drivers

* Per-room work is bounded by a constant (`max_sync_rooms`) and by the user's own rows.
* A room with news is never starved by idle rooms.
* The response of a sync is unchanged for a user within the cap.

## Considered Options

* `select_sync_rooms`: find the candidate rooms from the user's membership rows, drop on an incremental sync every room
  that cannot have news without charging the cap, and when more candidates than the cap remain, serve the most recent.
* Count only the rooms that end up in the response, as before ADR-0654.
* Do the per-room work for every room and stop emitting at the cap.

## Decision Outcome

Chosen option: the first.

* Candidates are the rooms of the user's `join` membership rows (`for_each_user_membership_row`), found by
  `find_local_room`, confirmed by `joined()`, and passing the room filter. They are in the order of `database.rooms`, so
  the response is built in the order it was.
* On an incremental sync (a `since` token and no `full_state`) a candidate is dropped when none of these holds, each
  an index lookup or a read of the room's own rows: its latest event stream position is above `since`; its typing stream
  position is above `since`; the user has a room account-data row of that room above `since`; the room holds a receipt row
  above `since`. These are a superset of what makes the room builder emit a room (events, state, account data, receipts and
  typing; a membership change and a limited timeline are both events), so no room with news is dropped. An initial sync
  and a `full_state` sync keep every candidate.
* When more candidates than `max_sync_rooms` remain, the cap's worth with the most recent latest event are served (ties by
  room ID): the rooms a client looks at first. Before this, the first rooms in storage order were.
* A room with news that is past the cap is not served by that sync and `next_batch` still moves on. That is what happened
  before ADR-0654 too (the 1001st room with news was skipped), so it is no worse; a user in more rooms than the cap
  that all have news at once loses the oldest of them until their next event. Raising `max_sync_rooms` is the operator's
  remedy. Holding `next_batch` back for such a room was rejected: the token is one position for the whole response, so
  it would make the rooms already served repeat.

### Negative Consequences

* The receipt part of the check reads the room's own receipt rows (bounded by the rooms' users times the threaded cap),
  not a single value; a per-room maximum would be one more index to keep in step.
* A room whose only news is a change the checks do not see would be dropped; there is none today, and a new source of room
  news must be added to `select_sync_rooms`.

## Links

* Refines ADR-0654. Uses ADR-0435 (room stream index), ADR-0440 (account-data index), ADR-0737 (receipt indexes).
