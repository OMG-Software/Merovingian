# Sliding-sync extension room lists share the room_subscriptions cap and are classified through one index

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `sp01.sliding-sync-extension-rooms-unbounded`

## Context and Problem Statement

The MSC4186 `receipts` and `typing` extensions take a client-supplied `rooms` array. Each named
room was classified with `room_access_for`, which scans every membership row in the store. For
receipts, each room then scanned every stored receipt. This all runs while the request holds the
global runtime lock. The arrays were uncapped and not de-duplicated, so one request body naming a
room thousands of times cost thousands of full scans of the membership and receipt tables.

## Decision Drivers

* The work done under `runtime.mutex` must not grow with input that one client controls.
* ADR-0172 already caps the other client-named lists in a sliding-sync request.
* An operator should not need another setting for what is the same kind of list.

## Considered Options

* Cap each array at the existing `room_subscriptions` limit, de-duplicate at parse time, and
  classify rooms through one membership index per request
* Add a separate, configurable cap for the extension arrays
* Keep the arrays uncapped and only make each room's lookup cheaper

## Decision Outcome

Chosen option: "cap each array at `room_subscriptions`, de-duplicate, and use one index".
`room_subscriptions` is the request's other list of client-named rooms, with the same per-room
cost, so the same operator-configured limit (default 256) bounds each extension array.
`sliding_sync_request_limit_violation` answers `400 M_INVALID_PARAM` past it.
`parse_sliding_sync_request` keeps each room ID once, in first-seen order, so repeats cost nothing
and do not count towards the cap.

`sync::room_access_index` classifies every room the user holds a membership in, in one pass over
the memberships. It must give `room_access_for`'s answer for each room, including the rule that on
an equal stream ordering the later row wins. A test pins that equivalence. `build_extensions`
builds the index once and shares it between receipts and typing. The `room_subscriptions`
classification in `client_server.cpp` uses it too. Receipts and typing then make a single pass
over their tables, grouped by the joined rooms that were asked for.

### Positive Consequences

* A request's lock-held work is linear in the store, not in the store times the request.
* The `"*"` (all subscribed) sentinel is unchanged. It names the response's rooms, which the lists
  and subscriptions already bound.

### Negative Consequences

* A client naming more than 256 distinct rooms in one extension is refused until an operator raises
  `room_subscriptions`. Element X sends `"*"`.

## Pros and Cons of the Options

### A separate configurable cap

* Bad, because it adds a setting with no independent reason to differ from `room_subscriptions`.

### Uncapped, cheaper lookups

* Bad, because the response still grows with the array, so the serialisation work under the lock
  stays unbounded.

## Links

* Follows [ADR-0172](0172-sliding-sync-sort-keys-are-computed-once-and-list-shape-is-capped.md)
