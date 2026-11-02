# A local event's depth comes from its prev_events and stops at the limit

* Status: accepted
* Date: 2026-11-02

Technical Story: security audit run-2 F-01, one rejected PDU at depth 2^53-1 stopped every local event in a room

## Context and Problem Statement

`next_depth_for_room` took the largest depth of every row stored for the room, rejected, soft-failed and
outlier rows included, and added one. Any server with a signing key could send one PDU at depth 2^53-1 for a
room with a local member. It was rejected and stored, the next local event got depth 2^53, the composer's own
canonical JSON parse refused that, and no local event in the room could be composed again, across restarts.

The spec fixes the rule (`rooms/v11.md`, `depth`) and clamps it. What it leaves open is where this server reads
the depth of a local event's predecessors, and a future reader might restore a room-wide scan with a status
filter because it looks simpler.

## Considered Options

* Depth from the event's chosen `prev_events`, through `depth_after_prev_events`, clamped
* Keep the whole-room scan, skip rejected rows, clamp
* Refuse inbound PDUs above some lower depth

## Decision Outcome

Chosen option: "Depth from the event's chosen `prev_events`", because it is the spec's definition, it needs no
list of statuses to keep up to date, and it looks up at most 20 events where the scan walked every event in the
store under `runtime.mutex`. The clamp stays because an accepted event from a joined server can sit at the limit.
A lower inbound ceiling was rejected: the spec allows any depth up to the limit, and refusing one would split
this server from the room.

Membership templates (`make_join`, `make_leave`, `make_knock`) use the same function for the prev_events they
offer.

### Positive Consequences

* A rejected or unrelated row cannot change the depth of a local event.
* A local join is deeper than everything it descends from, which is what ADR-0308's comparison relies on, and
  it is no longer raised above that by rows it does not descend from.

### Negative Consequences

* A local event at the limit shares its depth with its predecessors, so at the limit depth no longer orders them.
  The spec requires this.
* A local join can now be shallower than a rejected or soft-failed row. Those rows are not served to clients, so
  ADR-0308's comparison has nothing to get wrong for them.

## Links

* Refines [ADR-0308](0308-shared-history-visibility-orders-the-join-and-the-event-by-depth.md)
