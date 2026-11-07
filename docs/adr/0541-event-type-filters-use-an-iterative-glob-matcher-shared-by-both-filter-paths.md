# Event type filters use one iterative glob matcher, shared by both filter paths

* Status: accepted
* Date: 2026-11-07

Technical Story: analysis finding S3, `types` and `not_types` supported only `*` and a trailing `prefix*`

## Context and Problem Statement

The Filtering section of the Client-Server API says of `types` and `not_types`: "A `*` can be used as a
wildcard to match any sequence of characters." The matcher honoured `*` alone and a trailing star, so
`m.*.message` was an exact type that matched nothing, and a client's `not_types` exclusion silently failed to
exclude. Patterns and event types both come from clients.

## Considered Options

* `type_pattern_matches`: split the pattern at its stars and find each run leftmost, iteratively
* Compile the pattern to a regular expression
* A recursive matcher that tries every position for each star

## Decision Outcome

Chosen option: "`type_pattern_matches`", in `sync/type_pattern.hpp`, used by `event_passes_filter` and by
`PreparedRoomEventFilter`.

Regular expressions were rejected because the pattern is attacker-controlled and engines backtrack or
allocate unpredictably. A recursive matcher is exponential on `*a*a*a*b`. Taking each run at its leftmost
occurrence is correct (it leaves the most text for later runs) and never revisits an earlier star, so the cost is
at most `(n + m) * s` comparisons, n the type, m the pattern and s the longest run between stars. A run is
searched with `string_view::find`, not a failure table, so there is no allocation and the function stays
`noexcept`; the quadratic worst case needs a long run and a long type, both bounded by the request body limit.

`PreparedRoomEventFilter` keeps its hash set and sorted prefixes for exact and `prefix*` patterns (ADR-0332) and
scans a short list of general globs, those with a star before the last character. It must agree with
`event_passes_filter` for every pattern; the equivalence test in `test_prepared_room_event_filter.cpp` includes
globs. A change to one matcher is a change to the other.
