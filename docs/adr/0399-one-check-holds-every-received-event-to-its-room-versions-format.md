# One check holds every received event to its room version's format

* Status: accepted
* Date: 2026-11-04

Technical Story: security audit run 2, finding F-56: the 65536-byte limit and the `prev_events` and
`auth_events` caps were enforced in `parse_inbound_pdu_envelope` only, so an event fetched during backfill or
carried in a `send_join` answer could exceed them and still be stored, then be served to other servers.

## Context and Problem Statement

The spec's first PDU check is "Is a valid event, otherwise it is dropped", and that holds wherever the event
came from. The rules were written once for `/send`, and the other paths hold events as parsed values, or as
strings that take a different route to the store.

## Considered Options

* **One function over a parsed event, called on each path (chosen).**
* Copy the checks into each path. Rejected: that is how the paths came to differ.
* Add full identifier grammar checks for `room_id`, `sender` and the listed event IDs. Not done here: test
  fixtures across the suite use readable IDs such as `room_id + ":create"`, and a grammar check belongs in a
  change of its own that fixes those fixtures rather than in this one.

## Decision Outcome

`pdu_format_violation` (`src/federation/inbound_ingestion.cpp`) checks the canonical size limit,
`prev_events` and `auth_events` present as arrays within their caps, string entries from room version 3 on,
and no top-level `event_id` from room version 3 on (ADR-0397). `parse_inbound_pdu_envelope`,
`returned_pdu_is_well_formed` and `filter_verified_send_join_events` call it, and any new path taking events
from another server must too.

In a `send_join` answer, a dropped event cascades through the existing logic (ADR-0369): if the state can no
longer support the join, the join is refused.

Room versions 1 and 2 list `[event_id, hashes]` pairs, so entry types are only checked from version 3 on.

### Negative Consequences

* A resident that answers `send_join` with one oversized event may now make the whole join fail, where
  before the join succeeded and stored that event. This is deliberate: the event breaks the format.

## Links

* Refines [ADR-0397](0397-a-top-level-event-id-is-signed-and-refused-on-a-reference-hash-pdu.md)
