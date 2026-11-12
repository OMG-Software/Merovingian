# The state before an event is resolved and stored once per set of prev groups

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit C28,
`F-resource-exhaustion.state-groups.state-before-resolved-and-stored-per-pdu-without-reuse`. Extends
[ADR-0600](0600-a-room-remembers-its-last-resolved-state-by-its-distinct-state-groups.md) from a room's tips to the
state before each event.

## Context and Problem Statement

`compute_state_before` resolved the prev_events' groups afresh for every PDU with more than one prev_event, under
`runtime.mutex` and whatever the PDU's outcome, and `record_event_state` stored the result as a new group chained off the
first prev_event's group. When the resolution dropped a key that group held, the new group was a full snapshot, because
a delta cannot record a deletion. A remote member could name the same two old events in a stream of small PDUs, even
rejected ones, and each cost a resolution of the room's state and up to the whole room state in stored rows, kept in
memory and reloaded at every start.

How is the work and the storage of an event's state before made not to repeat for the same prev groups, without
changing any result?

## Decision Drivers

* A resolution's result must not change: this is a memo of a pure function, and what is refused stays refused.
* A rejected or non-state event adds no state rows.
* No schema change: the release is 1.0.1.

## Considered Options

* Keep the resolved state before as a group of its own, remembered by the distinct prev groups, and make it the delta
  parent of the event's after-state.
* Let a delta record deletions (a tombstone row), so a dropped key never forces a snapshot.
* A budget of stored state rows per origin.

## Decision Outcome

Chosen option: "Keep the resolved state before as a group of its own", because it removes the repeated resolution and
the repeated rows together, and needs no schema change.

* `compute_state_before` reads each distinct prev group once and still charges the budget once per prev_event, so
  what it refuses is unchanged. When every prev_event names one group, that group is the state before (resolving copies
  of one state set gives it back), as with one prev_event.
* Otherwise `PersistentStore::state_before_memo` (`StateBeforeMemo`) is asked for the room, the resolution context
  (room version and limits, as in ADR-0600) and the sorted distinct group IDs. A hit names a group that holds what
  resolving them gives; it is read, nothing is parsed or resolved. `StateBeforeResult::state_group_id` names the group
  whenever one is known.
* After a fresh resolution, `record_event_state` (the overload taking the `StateBeforeResult`) stores the result once
  as `sb:<event_id>` and remembers it. Its delta parent is the first resolved group that holds no key the resolution
  dropped, so the usual fork (one side's key dropped) is a delta of the conflicted keys, not a snapshot. The event's
  after-state is then chained off that group: a rejected or non-state event reuses it, a state event adds one row.
* The memo is in memory only, at most 1,024 entries, the oldest dropped first, and is forgotten with
  `resolved_state_memo` whenever an event its groups name changes (redaction, status change, reload). `find` is
  const and changes nothing (ADR-0525); every caller holds `runtime.mutex`.
* Why a hit stays right: a resolution reads the groups' rows, the events they and their auth chains name, and each
  event's status. Groups and events are insert-only (a plain `INSERT` on their primary key); the only writes that
  change an existing one are `set_event_status` (a rejected event re-accepted, a soft failure), `replace_event_json`
  (a redaction, a co-signed event) and `apply_room_snapshot` (a reload, which also drops groups), and each forgets the
  room before it writes. A resolution that meets a missing event fails and is not remembered, so a later arrival
  cannot make a remembered result stale. A new write path that changes an event or a group must forget the room too.

### Positive Consequences

* A stream of PDUs naming the same prev_events costs one resolution and one stored state before; after that, each
  costs reading that group (no parsing, no resolution) and adds at most one row.
* Two events with the same prev groups share one group of their state before.

### Negative Consequences

* Residual: each PDU still copies the state before out of its group (linear in the room's state, without parsing),
  because the auth checks and `compute_state_after` take the state as a vector.
* Residual: a fresh set of prev groups whose resolution drops a key every one of them holds is still stored as a
  snapshot. Such a set needs new forks, each of which is a PDU the sender pays for, and is stored once.
* A restart forgets the memo; the first event naming each set of groups after it resolves them once more.

## Pros and Cons of the Options

### Tombstones in deltas

* Good, because no state would ever force a snapshot.
* Bad, because every reader of `state_group_state` (the federation state reads, history visibility, the sync lookups)
  would have to learn tombstones at once, and the stored format would change in a patch release.

### A budget of stored rows per origin

* Good, because it bounds storage whatever the cause.
* Bad, because refusing to record an honest event's state leaves its room unable to resolve; the attacker chooses
  when the budget runs out.

## Links

* Extends [ADR-0600](0600-a-room-remembers-its-last-resolved-state-by-its-distinct-state-groups.md)
* Relates to [ADR-0525](0525-a-cache-that-is-not-thread-safe-is-not-hidden-behind-const.md)
