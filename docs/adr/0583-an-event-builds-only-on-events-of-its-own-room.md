# An event builds only on events of its own room

* Status: accepted
* Date: 2026-11-09

Technical Story: security audit run 4, finding F-01 (high).

## Context and Problem Statement

Every lookup behind a PDU's `prev_events` is by event ID alone: `find_missing_event_references`,
`find_event_state_group`, `read_state_group_full_state` and `compute_state_before`. A PDU in room A naming an event
of room B therefore took room B's state as the state before it, and was authorised against that. A remote member of
room A could be judged by a room where it held power, and the accepted event's state group and forward extremity
then mixed two rooms.

The room version's event format says `prev_events` are "the most recent events in the room", but no auth rule or
receipt check names the case, so nothing in the spec says what to do with one that is not. How should this server
treat it?

## Considered Options

* Refuse the PDU, at every path that takes one and in `compute_state_before`
* Treat a foreign `prev_event` as missing, so the ordinary gap recovery runs
* Check only in `compute_state_before`

## Decision Outcome

Chosen option: "Refuse the PDU", because a foreign `prev_event` is a statement the sender cannot honestly make: the
room's own graph does not hold it, and it will never arrive.

* `database::find_event_in_other_room` is the one test, one hash lookup per ID.
* `compute_state_before` refuses a foreign `prev_event`, and a `prev_event` of this room mapped to a state group of
  another room. Every resolution goes through it, so this holds whatever a caller checked.
* `ingest_pdu_event` answers `rejected_invalid` before it fetches anything, and again once the locks are back after
  the fetch, which may have stored the event the PDU names. The retry job treats that status as decided, and `/send`
  reports it as that PDU's error.
* The membership acceptor answers 400 `M_INVALID_PARAM`. `verify_and_store_backfilled_event` drops the event in
  every mode.
* An event the store does not hold is not asked about here. It is an ordinary gap, and the recovered copy is
  checked again.

Rows written before this version are not repaired: there are no users before 1.0 (ADR-0216).

### Negative Consequences

* Treating it as missing would have let a sender keep a retained row and a retry alive for an event that can never
  be placed, so nothing is retained; a server that sends such an event gets an error rather than a retry.

## Pros and Cons of the Options

### Treat a foreign prev_event as missing

* Bad, because the gap recovery would ask the sender for an event this server already holds under another room, and
  retain the PDU for a day of retries.

### Check only in compute_state_before

* Good, because it is one place.
* Bad, because it is reached after the fetch, so a foreign ID would first cost a network round trip, and the
  retained-PDU path would keep the event.
