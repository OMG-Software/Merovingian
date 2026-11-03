# The state at an event is read from the recorded state groups, never from a walk of the event graph

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, F-25 (rejected events served as state) and F-26 (the walk costs the whole
room history per request)

## Context and Problem Statement

Federation `GET /state/{roomId}` and `GET /state_ids/{roomId}` answer "the fully resolved state for the room,
prior to considering any state changes induced by the requested event" (Server-Server API v1.19), and the client
`GET /rooms/{roomId}/context/{eventId}` returns `state` as "the state of the room at the last event returned".
`reconstruct_state_at_event` answered both by walking every ancestor of the event and keeping, for each
`(type, state_key)`, the event with the greatest `(depth, event_id)`. That has two defects.

* It is wrong. Depth is chosen by the event's sender and is not checked against `prev_events` on receipt, and the
  walk read no status, so a rejected state event with the largest depth won its key over the true event and was
  served to peers and to local clients (F-25). It also ignored the state this server recorded for the event.
* It is unbounded. Every request parsed the stored JSON of every ancestor of the named event, to read `type` and
  `state_key` that `PersistentEvent` does not hold, so one authorised origin could occupy the shard's small
  `local_pool` with cheap GETs (F-26). ADR-0084 had already rejected this walk for per-event reads as a CPU
  amplifier, while noting that federation `/state` still used it.

## Considered Options

* Read the state this server recorded for the event (its ADR-0064 state groups).
* Keep the walk and filter out rejected events.
* Keep the walk and cap the number of ancestors it visits.

## Decision Outcome

Chosen option: read the recorded state. `federation::state_before_event` is the one function that answers it.

A state group holds the state AFTER its event (ADR-0084), and the federation answer is the state BEFORE the
event, so the group of the event itself is not always the answer:

1. The event is not a state event, or it is a rejected one: its state before equals its state after (a rejected
   event is recorded with the state before it, SS API "Rejection"), so its own group is the answer.
2. Otherwise, with one `prev_event`, the group of that `prev_event`.
3. Otherwise, with several, the resolution of their groups: `homeserver::compute_state_before`, the call
   ingestion makes, under a tighter budget (ADR-0365).
4. No `prev_events` (the create event): nothing precedes it, the answer is empty, and `/state` answers 404.

The client `/context` wants the state AT the event, which is its own group (`resolve_state_event_ids_at`): a state
event's own change is in it, and a rejected event's is not.

It fails closed, never falling back to a walk or to current state. An event with no recorded group (an outlier, the
events a federated join stores before the join), a missing or over-long group chain, a group that names an event this
store lacks or holds in another room, and a group that names a REJECTED event all make the state unknown. The
federation endpoints answer 404, which the spec allows for "the server doesn't know about the state at that event to
return anything useful"; `/context` returns an empty `state`. A state with a hole in it is never served as the room's
state. `/state` also refuses (404) a state event whose stored JSON does not parse, instead of skipping it.

Soft-failed events are in the answer exactly where resolution admitted them, because a soft-failed event's group is
recorded with its own change (SS API "Soft failure").

The cost of a request is the rows of the state-group chain (at most `max_state_group_delta_depth + 1` groups) and the
size of the state it returns, never the number of events in the room. `state_before_event` reports
`events_parsed` and `resolved` so a test can assert that.

### Positive Consequences

* A rejected event can never be state in an answer, whatever depth its sender gave it.
* `/state`, `/state_ids` and `/context` agree with the bookkeeping that authorises events.
* Per-request work no longer grows with room history.

### Negative Consequences

* A server that asks for the state at an event this server never recorded state for gets 404, where the walk
  returned a guess: the state before a federated join's own event, an outlier, an event whose `prev_events` this
  server lacks. The asker falls back to `/event` and `/get_missing_events`, as it must for any 404.
* `/context` for such an event shows an empty `state`.

## Pros and Cons of the Options

### Keep the walk and filter out rejected events

* Bad, because accepted or soft-failed events with an inflated depth on a losing branch would still win a key.
* Bad, because it is still one parse per ancestor.

### Keep the walk and cap the ancestors visited

* Bad, because a capped walk answers wrongly for any room with a longer history, and a wrong answer is worse than
  a refusal.

## Links

* Refines [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md), which recorded that
  federation `/state` still used the walk
* [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md) (state groups), [ADR-0325](0325-the-state-group-tables-own-their-rows-and-index-them.md) (their indexes)
* [ADR-0364](0364-a-state-answer-whose-auth-chain-is-over-the-bound-is-refused.md),
  [ADR-0365](0365-resolving-the-state-before-an-event-on-a-read-path-has-its-own-budget.md)
