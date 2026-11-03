# Search result context is built only when requested, from one pass over the events

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-31: `POST /search` walked the whole events table and sorted the room once per match, even when no context was asked for

## Context and Problem Statement

For every match on the page, `build_search_event_context` walked every row of the server's events table, collected
the match's room, sorted those rows and found the match by a linear search. It ran unconditionally, so a page of up
to 100 matches cost up to 100 walks and sorts under `runtime.mutex`, and a request with no `event_context` paid for
context it never showed. The spec says a result's `context` is "Context for result, if requested" and describes
`event_context` as configuring "whether any context for the events returned are included".

## Considered Options

* Build context only when the request carried `event_context`, and build every needed room's timeline in one pass
* Cache each room's sorted list on first use
* Build context only when requested but keep the per-match walk
* Add a per-room stream-order index to `EventTable`

## Decision Outcome

Chosen option: "Build context only when requested, from one pass". A request without an `event_context` object gets
results with `rank` and `result` and no `context` key. With one (even `{}`), `SearchRoomIndex`
(`homeserver/search_room_index.hpp`) is built once from the rooms of the page's matches: one walk of
`events.in_stream_order()`, which is already in stream order so nothing is sorted, filling each wanted room's list
and leaving out rejected and soft-failed rows (ADR-0064). A match is found in its room's list by binary search on
`stream_ordering`, with the event ID deciding among rows that share one. The index reports `table_walks()` (0 or 1)
so a test can hold it to that however many rooms and matches there are.

A per-room cache built on first use would still walk the table once per distinct room (up to the page size). An
`EventTable` per-room index would serve other callers but changes a storage structure kept in step with every write
path; one pass per request is enough here and leaves the table alone.

Before this change a result always carried a `context` (a default of 5 events either side); a client that read it
without asking now sees none. That follows the spec; the conformance scenario that read it unasked was updated.

### Positive Consequences

* A search with no `event_context` does no context work. One with it walks the table once, whatever the page size.

### Negative Consequences

* A client relying on the unrequested context must send `event_context`.
* `max_search_context_events` (default 100 events per side per match) still bounds the response size separately.

## Links

* Follows [ADR-0330](0330-search-terms-are-matched-in-linear-time-and-capped-at-1024-bytes.md)
