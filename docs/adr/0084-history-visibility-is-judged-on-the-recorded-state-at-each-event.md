# History visibility is judged on the recorded state at each event, one filter per request, and fails closed

* Status: accepted
* Date: 2026-09-30

Technical Story: findings CSAZ-2 and CSAZ-3 (high) in
`docs/security-audit-report-2026-09-29.md`.

## Context and Problem Statement

No client read path consulted `m.room.history_visibility`, and `initialSync`, `/members` and
`/state` admitted any membership row (a knock, an invite, a declined invite) and served the
room's current state to users who had left or been banned. The spec decides which events a user
may see from "the state of the room *at that event*" (five rules, plus a before-or-after
relaxation for `m.room.history_visibility` events and the user's own `m.room.member` events),
and gives a user who has left "the state of the room when they left". How the server finds the
state at an event, how it keeps a page of events cheap, and what it does when it cannot tell
are decisions.

## Decision Drivers

* The filter is applied to every event on every read path, so it has to be O(1) per event after
  a per-request warm-up, not a walk of room history per event.
* A missed read path is a disclosure, so there must be one rule and one place to call it.
* The store holds only the latest membership per (room, user); the history of joins is only in
  events and state groups.

## Considered Options

* Reconstruct the state at each event by walking the event DAG (`reconstruct_state_at_event`,
  what `/context` and federation `/state` do).
* Linearise by stream ordering: the visibility and the user's membership "at" an event are the
  latest such events with a lower stream ordering.
* Read the state group recorded for the event (ADR-0064), cached per group per request; take
  "before" from the `state_transitions` predecessor; deny when there is no state.

## Decision Outcome

Chosen option: the third.

* **`sync::HistoryVisibility` is the one filter.** One instance per request and user. It maps an
  event to its ADR-0064 state group (the state immediately after the event), resolves the
  history visibility and the user's membership from that group's delta chain (bounded and
  cycle-checked like `read_state_group_full_state`), and caches the answer per group, so a page
  costs one lookup per distinct state group. Its indexes over the store are built lazily, once
  per instance.
* **"Before" comes from the recorded predecessor.** For the two special cases the state before
  the event is the `previous_event_id` of the event's `state_transitions` row (computed from the
  event graph when it was stored), not a second group lookup, which would need state
  resolution over several `prev_events`.
* **"Joined after the event" is stream ordering.** The newest accepted join event of the user
  in the room is found by scanning state group rows for the user's `m.room.member` entries (no
  JSON parsing of the room's events) and compared with the event's `stream_ordering`.
* **Fail closed.** A broken group chain, a group that names an event the store does not hold,
  or a rejected or soft-failed event is not visible. There is no fallback to the current state.
* **An event with no state group gets rule 2 alone.** History stored before ADR-0064 (migration
  015 seeded only forward extremities) has no recorded state, so the visibility at the time
  cannot be proved and hiding all of it would strip every existing deployment of its history on
  upgrade. For such an event the user sees it only if their latest membership at or before its
  stream ordering was `join`, taken from the chain of their own `m.room.member` events
  (`state_transitions` predecessors from their current member state). Rule 2 allows an event
  under every visibility, so this can only show a subset of what the spec allows. An
  undeterminable chain (a missing event, a cycle) denies. Events that have a state group keep
  the full five-rule check and both special cases.
* **`sync::room_read_access_for` gates state reads.** `current` for a user whose membership row
  is `join` (or, with no row, whose current state says `join`); `as_of` for a row of `leave` or
  `ban` when the chain of the user's `m.room.member` events shows a join before it, bounded by
  the event that ended that join; `none` otherwise, including a declined invite, a knock and a
  forgotten room. `/members?at=` and a departed user's reads are capped at that event.
* **Peeking is decided on the room's current visibility.** A user with no read access may read
  events (`/messages`, `/event`, `/context`, `initialSync`) only when the room's *current*
  visibility is `world_readable`; which events are then returned is still per event. `/members`,
  `/state` and `/state/{type}/{key}` have no peek exception because the spec's 403 text for them
  has none.
* **Pagination moves past hidden events.** `/messages` reports as `end` the last event it
  examined, hidden or not, and examines at most `max_messages_events_examined` events per page.

Rejected alternatives:

* *DAG walk per event.* It is the existing `/context` mechanism, and it is correct, but it is
  O(room history) per event; a `/messages` page would be quadratic, and every read path would
  have become a CPU amplifier.
* *Stream-ordering linearisation.* Cheap, and exact for a fork-free room, but wrong exactly when
  it matters: a federated room with forks has a state at an event that is not the latest
  visibility event below it in arrival order. The state group is the recorded answer.
* *Fall back to current state when an event has no state group.* It looks friendlier to rooms
  that predate state groups, and it is a disclosure: current state says nothing about what the
  user could see at that event.
* *A deny-list at each call site.* Nine read paths would each re-derive the five rules; the next
  path added would forget.

### Positive Consequences

* One rule, tested directly (`tests/unit/test_sync_history_visibility.cpp`) and per read path
  (`tests/conformance/test_history_visibility_conformance.cpp`).
* A page of events costs one state lookup per distinct group.

### Negative Consequences

* History stored before ADR-0064 state groups existed is visible only to users who were joined
  when it was sent; `shared` and `world_readable` history from that period is not shown to
  anyone else (a later joiner, or a peeker) until state is recorded for it.
* An event stored without a `state_transitions` row gets no before-or-after relaxation; that
  errs towards hiding it.
* A late-arriving (backfilled) event has a stream ordering after the user's join, so rule 3 does
  not see the join as "after"; the state at the event alone decides.

## Links

* Builds on [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md) (state
  groups, `state_transitions`, event status).
* Related: the federation read gate, `federation::origin_may_read_room` (finding FED-2), judges
  current state only and is deliberately separate.
