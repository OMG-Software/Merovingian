# Current state drops a key the resolution does not hold, and keeps a row from outside the graph

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, medium findings (a defect found while fixing them).

## Context and Problem Statement

`recompute_current_state` wrote every resolved entry that differed from the cached `current_state`, and never removed a
key the resolution did not hold. A key only a losing fork set (a member row, `m.room.server_acl`, `m.room.name`) stayed in
`current_state` for good. The spec's current state is the resolved state.

Not every row in `current_state` comes from the room's graph, though. Which rows may be removed?

## Decision Drivers

* An invite or a leave for a room this server is not in, or has left, is written as an outlier with a `current_state`
  row and no state group (`LocalHttpRouter.cpp`, `RoomService.cpp`). The room's tips know nothing of it.
* A `/state_ids` or `send_join` snapshot stores events as outliers with no state group of their own, but a tip's recorded
  state names them.
* An empty set of tips, or a refused resolution, says nothing about what the state is.
* ADR-0225 and ADR-0373 record a fallback event's state before from `current_state`. Keys in that state are in the event's
  state group and so are in the next resolution; they are not removed.

## Considered Options

* Delete every row whose key the resolution does not hold.
* Delete a row only if its event has a state group.
* Delete a row if its event has a state group or a tip's recorded state names it; keep the rest.

## Decision Outcome

Chosen option: "Delete a row if its event has a state group or a tip's recorded state names it; keep the rest".

* A row kept is one whose event has no state group and that no tip's state names: it was written outside the graph, and
  a resolution over the graph cannot speak to it. Deleting every absent row would lose an invite a user has not answered.
* Nothing is deleted when the room has no tips or the resolution is refused.
* Tip state is read only when a kept-class candidate exists, once per distinct state group, and stops once every candidate
  is named. It costs what one resolution's read of those groups costs, which `max_state_groups` and the state budget bound.
* `database::remove_current_state_rows` commits the deletes and the membership corrections in one transaction, on both
  backends, then mirrors them, keeping `state_position_index` and `state_room_index` in step: holes are filled from the
  end of `state`, and only the rooms that lost or moved a row have their position list rewritten.
* A removal writes no `state_transitions` row. That table records what an event replaced.
* A membership row follows a member key the recomputation removes (to `leave`) or changes (to the resolved event's
  membership). It is left alone when it says other than `join` and is newer than both the event the key held and the
  resolved event: a row like that was written by an invite or a federated leave with no state behind it, as in
  `reconcile_memberships_with_current_state`. A corrected row takes at least the stream ordering of the event that
  caused the recomputation, so `/sync` sees it. A row whose key did not change is not touched.
* `CurrentStateRecompute::membership_changes` hands the corrections to the two callers, which apply them to the live
  roster with `apply_membership_to_roster`.

### Positive Consequences

* A key from a losing fork, such as a server ACL or a member, stops having effect as soon as the resolution drops it, and
  stays gone after a restart.

### Negative Consequences

* `store_event_with_bookkeeping`, which places a local event, does not remove keys. A local event's state before is
  already resolved, so its diff has nothing to remove unless the room's tips changed before it; the next inbound
  recomputation removes what is left.
* A removal is not delivered as a state change in `/sync`'s `state` section, since no event replaces the key. A member's
  removal is seen through the membership row.
