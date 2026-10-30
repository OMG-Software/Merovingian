# A backfilled outlier with a state group is held

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestGetMissingEventsGapFilling` regressed after ADR-0289: the first
`/sync` held only the newest event, `limited` and without the five events `get_missing_events` had
just filled.

## Context and Problem Statement

[ADR-0289](0289-a-hole-in-the-event-graph-makes-a-sync-timeline-limited.md) defined an event as held
when `store.events` has a row for it whose status is not `outlier`. But the events fetched by
`/get_missing_events`, `/event` and `/backfill` (`verify_and_store_backfilled_event`) are stored with
status `outlier` too, and they are legitimately in the graph: the writer computes each one's state
before it from its own `prev_events` and records a state group for it. The event that named them
had them as predecessors, so `/sync` saw a hole before it, cut the window to that one event, and
dropped the filled events.

## Considered Options

* Treat every outlier as held again.
* Treat an outlier as held when it has a state group.
* Change the status the backfill writer gives what it fetches.

## Decision Outcome

Chosen option: an outlier is held when it has a state group (`HistoryVisibility::has_state_group`).
A state group exists only for an event whose state was computed from its prev_events, that is, one
placed in the graph; ADR-0070 already treats a prev_event with no state group as missing
(`collect_missing_pdu_references`), so the two definitions of "present" agree. A `send_join` state or
auth-chain outlier, an invite or leave stub, and an event stored on the strength of its own
auth_events alone (ADR-0069) have none and stay not held. The same test decides whether an event is
the subject of the hole check, so a never-placed outlier still never starts a limited timeline.
The lookup is the per-request, once-built event-to-group index of `HistoryVisibility`; no scan of
the store per event.

Rejected: treating every outlier as held would hide the holes ADR-0289 exists for (an event whose
predecessors were only ever received as auth-chain outliers). Changing the writer's status would
touch the ADR-0064 receipt-order meaning that other readers depend on.

## Links

* Refines [ADR-0289](0289-a-hole-in-the-event-graph-makes-a-sync-timeline-limited.md) (the definition of held)
* Relates to [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md), ADR-0069, ADR-0070
