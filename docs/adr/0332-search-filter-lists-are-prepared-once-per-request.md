# Search filter lists are prepared once per request

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-30: `POST /search` multiplied client-sized filter lists by the events it scans, with `runtime.mutex` held

## Context and Problem Statement

`POST /search` takes `keys` and a RoomEventFilter (`rooms`, `not_rooms`, `senders`, `not_senders`, `types`,
`not_types`). Each list was kept as a vector and scanned for every event: `room_passes_filter` for every event of
every room the user has been in, `event_passes_filter` and a `std::ranges::find` over `keys` for every examined
event. The only bound on a list was the 1 MiB body (about 260,000 entries), so one request cost the list length times
the events scanned, about 2.6e9 comparisons, with the global lock held. The spec gives no maximum for any of the
lists, so refusing a long one would refuse a valid request.

## Considered Options

* Prepare the lists once per request into structures whose per-event cost does not depend on their length
* Refuse a list over a cap with `400 M_TOO_LARGE`
* Truncate or deduplicate the lists in place and keep scanning

## Decision Outcome

Chosen option: "Prepare the lists once per request".

* `keys` is resolved at parse time to a bit mask of the three keys the spec lists (`content.body`, `content.name`,
  `content.topic`). An empty list means all three; entries that name nothing else are ignored, so a list of unknown
  keys matches no event, as before.
* `sync::PreparedRoomEventFilter` (`sync/sync_filter.hpp`) holds `rooms`, `not_rooms`, `senders` and `not_senders` as
  hash sets and `types` and `not_types` as a hash set of exact types and a sorted list of `prefix*` patterns from
  which any pattern covered by a shorter one is dropped. No kept prefix is a prefix of another, so at most one can
  match an event type, and it is found by binary search. A request's `PreparedRoomEventFilter` is built once in
  `parse_search_request` and used for the gather, the scan and the context pages; each judgement costs hash lookups
  and one binary search, whatever the list lengths.
* `room_passes_filter` and `event_passes_filter` stay as they are for `/sync`, `/messages` and `/context`, which judge
  few events with short lists; the prepared class gives the same answers for the same lists, and a test holds them
  to it. `*` is supported only as the whole pattern or as the last character, as `matches_type_pattern` does; a
  `*` elsewhere in a pattern (which the spec allows) is a separate gap that both would have to close together.

Refusing past a cap was rejected because the spec sets none and a client with a long but valid list would be
refused; deduplicating in place still leaves a scan per event.

### Positive Consequences

* Per-event filter cost does not grow with the request's lists.

### Negative Consequences

* Two implementations of the same filter rules exist; the equivalence test must be extended with any new rule.
* Building the sets is linear in the lists, once per request, and is bounded by the body.

## Links

* Follows [ADR-0330](0330-search-terms-are-matched-in-linear-time-and-capped-at-1024-bytes.md)
