# Events verified only against their auth_events carry no state

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-27

Technical Story: 0.12.13 security branch, decision D1 in
`docs/todos/audit-0.12.13-handover.md`. Amends the implementation of
[ADR-0069](0069-spec-conformant-state-ids-fallback-via-event-auth.md).

## Context and Problem Statement

The ADR-0069 `/state_ids` fallback verifies a historical snapshot state event
whose `prev_events` have no local state by fetching its auth chain through
`/event_auth` and authorising it against its own `auth_events` alone. As first
implemented, such an event was then given a recorded after-state of its own
`auth_events` plus itself.

That after-state is not the room's state after the event; it is a thin state
the origin chose by choosing the event's `auth_events`. Any later PDU naming
the event as a `prev_event` was authorised (spec receipt step 5, "the state
before the event") against that thin state. Only the current-state check
(step 6) and state resolution stood between that PDU and the room.

What state, if any, should an event verified only against its own
`auth_events` carry?

## Decision Drivers

* Spec, server-server-api.md "Checks performed on receipt of a PDU", step 5:
  a PDU must pass authorisation against the state before it, which is the
  resolved state after its `prev_events`. A state the origin chose is not
  that state.
* The ADR-0064 rule that a remote server's claim about historical state is
  never used without verifying it.
* The fallback must keep working for honest rooms.

## Considered Options

* **No state (chosen).** Store the event as a true outlier with no state
  group. Record one later, only if the fallback supplies a verified state
  before it and the event passes authorisation against that state.
* **Thin after-state (as first implemented).** Record the event's own
  `auth_events` plus itself as its after-state, and document the residual
  risk that descendants are authorised against it.

## Decision Outcome

Chosen option: "No state", because it removes the residual risk instead of
recording it, and costs honest rooms at most one more `/state_ids` round trip
when a PDU builds directly on such an event.

How it works (`verify_and_store_backfilled_event`,
`src/homeserver/local_http_router.cpp`):

* An event stored through the `/event_auth` path has no state group.
  `collect_missing_pdu_references` already treats a `prev_event` without one
  as missing, so a PDU that builds on it triggers backfill of the state at it.
* When a later `/state_ids` fallback targets an event already stored without a
  state group, the event is authorised against the verified snapshot. If it
  passes, it gains a state group and keeps its stored status. If it fails, it
  is left without state and nothing can build on it.
* A stored event whose room differs from the room being backfilled is never
  given state: in room versions 1 and 2 event IDs are not content hashes.
* The snapshot loop skips any event already stored, not only events with a
  state group, so an `/event_auth` outlier is not fetched and re-verified
  every time a later snapshot names it. The snapshot is still built from the
  stored copies, which are checked for room, rejected status and state-event
  shape.

### Positive Consequences

* No PDU is authorised against a state the origin assembled from an event's
  `auth_events`.
* Events stored before ADR-0064's state groups also gain state through the
  same promotion path when a snapshot supplies it.

### Negative Consequences

* A PDU whose `prev_event` is an `/event_auth` outlier costs another
  `/state_ids` fallback before it can be accepted, and is held as
  `missing_prev_state` if the origin cannot supply that state.

## Links

* Amends [ADR-0069](0069-spec-conformant-state-ids-fallback-via-event-auth.md)
* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
* Tests: `tests/integration/test_pdu_ingestion_backfill_flow.cpp`, tag
  `[event_auth_outlier]`
