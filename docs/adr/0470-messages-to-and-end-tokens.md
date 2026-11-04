# GET /messages: `end` is omitted at the end of history, and `to` is a boundary in the same plain token space as `from`

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET /rooms/{roomId}/messages` always sent `end` (an empty string when nothing was examined) and never read `to`. The spec
says `end` is omitted when no further events are available and that a client "should continue to paginate until no `end`
property is returned". An empty `end` passed back as `from` is treated as no `from`, so a client followed it to the newest
events again. `to` is "the token to stop returning events at".

## Decision Outcome

`end` is the stream ordering of the last event examined, sent only when the walk stopped with an event still to consider
(page full or examination budget spent, before `to`). Reaching the start (or end) of the timeline, or `to`, omits it.
It is not judged whether the remaining events are visible to the user: the spec's "may not have permission to see any
more events" is met by a following request that finds nothing and omits `end`.

`to` uses the token forms `from` takes. A plain token T stops at the event with ordering T (backward: events at or below T
are not returned; forward: events at or above T). A `/sync` `next_batch` names a position just after its newest event N, so
backward stops at N and forward at N + 1. An unparseable `to` is ignored, as an unparseable `from` is.

Rejected: always send `end` and let an empty chunk end pagination. The spec says an empty chunk does not imply the end.
