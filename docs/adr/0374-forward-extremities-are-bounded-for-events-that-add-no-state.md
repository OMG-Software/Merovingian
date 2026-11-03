# Forward extremities are bounded for events that add no state

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-49
(`state.recompute-refusal-reports-success-leaves-unresolved-current-state`). Refines
[ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md).

## Context and Problem Statement

Every accepted inbound PDU becomes a forward extremity and removes the events it cites. A remote
member could cite one old event from many messages: each stays a tip, nothing capped the number per
room, and `recompute_current_state` refuses to resolve more than `max_state_groups` (default 1000)
extremities. While it refused, `current_state` changed only through each accepted event's own row, so
a demoted moderator's concurrent state change stayed current. The spec limits `prev_events` to 20 per
event; it does not limit how many extremities a server holds ("should" cite every event it has not
seen a child of).

How do the tips of a room stay few enough to resolve, without letting a flood push a ban or a
demotion out of the resolution?

## Decision Drivers

* A ban or demotion must reach resolution whatever the room's message forks.
* Choosing by `depth` is choosing by the sender (ADR-0225 made the same point for the fallback).
* No work under `runtime.mutex` may grow with input a remote server chooses.
* A room where resolution succeeds must behave as before.

## Considered Options

* Resolve extremities that share a state group as one state, and do not make a non-state event a tip
  past the limit.
* Resolve a bounded set of the newest tips by this server's stream order.
* Store every fork past the limit as soft-failed, whatever its type.
* Leave the count unbounded and only report the refusal.

## Decision Outcome

Chosen option: "Resolve extremities that share a state group as one state, and do not make a
non-state event a tip past the limit".

1. `resolve_extremity_states` groups extremities by the state group that holds their after-state
   and resolves each distinct group once. A message adds no state, so its after-state is its
   prev_event's group (`create_or_reuse_state_group` reuses the parent); a flood of messages that cite
   one old event is one state, and the limit and the budget count distinct groups. This changes no
   result: resolution is over a set of states.
2. `forward_extremities_stay_bounded` (called by `ingest_pdu_event`) refuses tip status to an accepted
   event that has no `state_key` and cites no current tip while the room already holds
   `max_state_groups` tips. An event that cites a tip replaces it and never grows the set. Such an
   event is still stored, delivered and given its state group, and later events that cite it are
   placed by its own prev_events as usual; it is only not cited by this server's next local event.
   The extremity table is bounded for message floods (storage and the per-PDU pass over the tips).
3. A state event is never refused tip status. A ban, a kick or a demotion is a state event that an
   honest server may legitimately build on an event this server no longer holds as a tip (its own
   view lacks the attacker's fork), so refusing it would drop the very revocation that must win.

### Positive Consequences

* The reported attack (1001 messages citing one event) resolves, so a demotion arriving during it
  reverts the demoted sender's concurrent state, because both tips reach resolution.
* Ordinary rooms are unaffected: below the limit every event is a tip, as before.

### Negative Consequences

* A member can still hold more than `max_state_groups` distinct state tips by sending that many state
  events (for example profile changes, each citing an older event). Then the recomputation is
  refused (ADR-0375). This needs one accepted state event per tip.
* Past the limit a message is not a tip and this server's next event does not cite it; another server
  that does cite it is placed normally. A DAG that is not fully covered by `prev_events` is allowed
  ("should").

## Pros and Cons of the Options

### Resolve the newest tips by stream order

* Good, because it bounds the resolution input whatever the type.
* Bad, because the newest tips are the attacker's: a flood after a ban pushes the ban tip out of the
  resolution, and the recompute then writes the older state over it.

### Store every fork past the limit as soft-failed

* Good, because it is simple and bounds storage.
* Bad, because a ban by an honest server that cites the attacker's common ancestor would itself be
  a fork past the limit and be dropped.

### Leave the count unbounded and only report the refusal

* Bad, because nothing then stops a flood from keeping the refusal in place.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
* Related: [ADR-0373](0373-a-fallback-event-records-the-rooms-current-state-as-its-state-before.md), [ADR-0375](0375-a-refused-recomputation-of-current-state-is-a-status-not-a-success.md)
