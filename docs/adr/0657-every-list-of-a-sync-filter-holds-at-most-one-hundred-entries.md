# Every list of a sync filter holds at most one hundred entries

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C09 (uncapped type-pattern lists matched per row).

## Context and Problem Statement

A user may store a filter of up to 1 MiB, and neither the upload check nor the parser capped the length of any list. A
`types` or `not_types` list of 100,000 wildcard patterns is then matched against every account-data row, every examined
timeline row, every state row and every presence row of every `/sync` that uses the filter, under `runtime.mutex`.

## Decision Drivers

* The work a filter adds to one sync is bounded by a small constant per row, whatever filter the user stored.
* A filter stored before the cap, and one given inline, must be held to it as well.
* The parse functions are deliberately lenient (a malformed field is ignored, not an error).

## Considered Options

* A cap of 100 entries per list (`types`, `not_types`, `senders`, `not_senders`, `rooms`, `not_rooms`, `event_fields`)
  checked at upload and again whenever a filter is used, refused with 400 `M_INVALID_PARAM`.
* A hash set for exact types and a cap only on wildcard patterns.
* Truncating a long list when it is parsed.

## Decision Outcome

Chosen option: the first.

* `validate_filter_definition` (upload) refuses a list over `max_filter_list_entries` (100). `filter_list_cap_problem`
  walks the lists the parser reads, in an uploaded or inline `Filter` and in the flat `RoomEventFilter` that `/messages`
  and `/context` take, and `GET /sync` calls it after the filter has been resolved, so an inline filter and a stored one
  are refused alike. `/messages` and `/context` call it before parsing the filter argument. The lenient parsers do not
  refuse: `POST /search` and sliding sync parse their filters through `parse_room_event_filter_argument`, and search
  already matches long lists through a prepared filter (its own conformance test holds lists of 20,000 entries), so
  the cap is applied by the endpoints that match a filter's lists against rows with the plain scan.
* Truncating was rejected: a filter with 101 entries that silently drops the last would show a client events it asked to
  hide (a `not_types` or `not_senders` entry) or hide events it asked for.
* A hash set for exact types was rejected as unnecessary once the cap bounds the list at 100; it would add an index to
  keep in step for no further bound.
* The stored form is not rewritten: a filter stored with more than 100 entries stays in the table and every sync that
  names it is refused, which tells its owner to upload a smaller one.

### Negative Consequences

* A client that uploaded a longer list before this release gets 400 `M_INVALID_PARAM` on the sync that uses it.

## Links

* Builds on ADR-0616 (the timeline skip budget) for the other factor of the cost.
