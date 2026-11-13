# A filtered directory request parses a bounded number of bytes

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C24 (resource-exhaustion.public-rooms-search.filtered-listing-parses-every-published-room-under-runtime-mutex)

## Context and Problem Statement

`public_rooms_response_json` walks every published room for each request. With a `generic_search_term` or a `room_types`
filter it read and fully parsed each room's create, name, topic and canonical alias events, whether or not the room landed in
the page, so the page size bounded only the output. A local user can publish rooms without a per-user cap, each with a name and
topic near the 64 KiB event limit, and any authenticated user or federating server can repeat the request. About 1,000 such
rooms made each search parse about 128 MB under `runtime.mutex`.

## Decision Drivers

* The paging tokens are offsets into the rooms that match, so a scan cannot resume from a position in the room list.
* The spec lets a server answer a search with fewer results than exist; it has no "too expensive" error.
* The unfiltered listing is already bounded by the page.

## Considered Options

* A per-room directory summary updated whenever a name, topic, alias or type changes
* A cap on the rooms examined per request, with a `next_batch` from where the scan stopped
* A byte budget on the state events one filtered request parses, after which no further room is examined

## Decision Outcome

Chosen option: the third. `public_rooms_response_json` takes `max_examined_bytes` (default
`max_public_rooms_examined_bytes`, 4 MiB). Each state event a filter or search reads is charged at its stored size before it
is parsed; once the budget cannot pay for one, that room and every later room are skipped (still counted in
`total_room_count_estimate`). The rooms of the page itself are read without the budget, as before: a page is bounded by its
size and `max_page_bytes`.

### Positive Consequences

* A search parses at most 4 MiB of events under the lock, not 128 MB.
* No new state to keep consistent, and paging semantics are unchanged.

### Negative Consequences

* A search over a directory whose events total more than 4 MiB can miss matches in the rooms past the budget. Ordinary
  rooms (a few hundred bytes of name and topic) give thousands of rooms per budget.

## Pros and Cons of the Options

### A per-room summary

* Good, because search would cost nothing per request.
* Bad, because it is a new index that must be right on every change, delete and load (ADR-0344), and a larger change than the
  finding needs. A follow-up may still do it.

### A cap on rooms examined with a resumable token

* Bad, because the tokens count matches, not rooms, so resuming needs a different token scheme.

## Links

* Refines [ADR-0460](0460-one-listing-and-one-strict-reader-serve-the-published-room-directory.md)
