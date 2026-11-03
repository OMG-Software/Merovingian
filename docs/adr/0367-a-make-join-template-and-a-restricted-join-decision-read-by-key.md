# A make_join template and a restricted-join decision read the state by key and by room

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-19 (`fed.make-join-template-global-event-scan-uncapped-prev-events-under-mutex`)

## Context and Problem Statement

`GET /make_join` is answered in main under `runtime.mutex` (ADR-0184), for any room this server holds, by any
authenticated federating server. The template provider picked its auth events with a pass over the whole server's
`store.state`, and `decide_restricted_join`, which runs for every make_join even in an unrestricted room, passed over
`store.state` twice and `store.events` once more. Its `prev_events` were also rebuilt from every row of the room's events;
PR #549 (ADR-0318) already replaced that with `forward_extremities_for_new_event`: at most 20 accepted tips, a depth taken
from those tips alone, and `nullopt` for a room with none (ADR-0301), never an empty `prev_events`. What remained was the
cost of the other reads, which followed the size of the server and not the room.

## Decision Drivers

* A cost under `runtime.mutex` follows the room and the rooms its join rule names, not the server.
* The restricted-join decision must stay exactly as spec-correct as run-1 left it (ADR-0185, ADR-0171).
* No new data structure: ADR-0344 already indexes current state by room, type and key.

## Considered Options

* Read through `find_current_state_event_id` and `for_each_room_state_row`, and events through `EventTable::find_in_room`
* Add a per-room index of the events a join needs
* Cache the decision per room

## Decision Outcome

Chosen option: "the existing state index and the event table's per-room lookup".

* The template's auth events are four lookups by key (create, join rules, power levels, the user's member event).
* `decide_restricted_join` finds the room's create, join rules, power levels and the joiner's member event by key, and
  parses the create and join rules events before anything else; an unrestricted room costs those and no more. The allow
  conditions are read in order until one holds: each named room costs a lookup of its create event and the joiner's member
  event, and one walk of that room's own member rows for this server's users. A room named twice is read once.
  The authorising candidates are the walk of the room's own rows, or one lookup when the join already names its authoriser.
* `stored_room_version` (every make_join and every membership event) reads the create event through the index too.
* `RestrictedJoinDecision::work` counts the state rows visited and the events parsed, so a test can show the cost is the
  same with unrelated rooms present.

### Positive Consequences

* A make_join in an unrestricted room is a few hash probes and two small parses, whatever else the server holds.

### Negative Consequences

* `store.rooms` (the existence check) and `store.forward_extremities` (`find_forward_extremities`) are still flat vectors
  scanned once each; they grow with the number of rooms, not with events or state rows. A per-room index of them is a
  separate change.

## Pros and Cons of the Options

### Cache the decision per room

* Bad, because a decision is read from state another server can change at any time; a stale "authorised" admits a join.

### A per-room index of events

* Bad, because `EventTable` already looks an event up by ID and room; the cost was the scans, not the lookups.

## Links

* Related: [ADR-0185](0185-a-resident-authorises-restricted-joins-only-after-checking-the-allow-conditions.md) · [ADR-0318](0318-a-membership-template-offers-the-rooms-stored-forward-extremities.md) · [ADR-0344](0344-index-current-state-by-room-type-and-key-and-trust-it-only-while-in-step.md)
