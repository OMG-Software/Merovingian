# A left room's `state_after` stops at what the user may read, and always holds their own membership

* Status: accepted
* Date: 2026-11-16

## Context and Problem Statement

A left room's `state_after` is "The state updates for the room up to the **end** of the timeline", and that timeline runs
"up to the point when the user left". A left room's incremental `state` holds only the leave, and only when the timeline does
not carry it ([ADR-0453](0453-sync-honours-full-state.md) kept that). A `state_after` client takes no state from the
timeline, and a user who left may not read the room after they left, whatever a later ban changes
([ADR-0357](0357-a-left-rooms-sync-state-is-gated-by-room-read-access.md)).

## Considered Options

* Reuse the joined room's delta, against current state (rejected: it tells a departed user what happened after they left)
* Keep `state`'s rule and send the leave alone on an incremental sync (rejected: "the state updates up to the end of the
  timeline" hold what changed before the leave too)
* Read the state only as far as `room_read_access_for` allows, take away what the client held at `since`, and add the user's
  own membership event

## Decision Outcome

Chosen option: the last (`build_left_room_state_after`).

* The room's state comes from the state anchor of `room_read_access_for`, capped at the event that ended the join.
* The user's own key is always the current member event, sent even when the timeline carries it. For a user who left and
  was banned since, the room is as of the leave and the membership is the ban, the one thing the room's state may say about
  after the leave.
* A `since` at or past the end of what the user may read (they left before it, and were banned after it) leaves only that
  membership event.
* A user who never joined (`none`) gets only their own event, as on `state` (ADR-0357).
* A client holds the room's state at `since` only if it was joined then. When the join this departure ended began after
  `since` (`RoomReadAccess::join_ordering` above `since`: a join and leave inside one window, or a rejoin after an earlier
  departure), nothing is taken away and the whole readable state as of the leave is sent, as an initial sync would, still
  capped by `room_read_access_for`; lazy-loading then treats the room as new to the client (the tracker is not consulted).
  The join's ordering comes from the walk of the user's member events that already finds the boundary, so no scan of the
  room's rows decides it. It is the rule `joined_membership_changed_since` applies to a joined room, read from the join
  event because a departed user's current member event is the leave. Subtracting what the client "held" would have hidden
  the create event, power levels and join rules from a client that is never told them another way.
* `full_state=true` does not make a left room's `state_after` whole: `full_state` is about "all rooms the user is a member
  of" and the Left Room `state_after` does not name it, as ADR-0453 has for `state`.
* With lazy-loading, a sender's member event is looked up as of the leave. When the state group chain cannot be read it is
  omitted, while a joined room lets the current member event stand in: omitting a member is a smaller harm than telling a
  departed user a later one.

### Consequences

* A left room's state always costs two whole reads, of that room's rows. Leaves are rare and once per room per client.
