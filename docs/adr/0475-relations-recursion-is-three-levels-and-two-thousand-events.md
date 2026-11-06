# A recursive relations walk is three levels deep and examines at most 2048 events beyond the first

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET /rooms/{roomId}/relations/{eventId}?recurse=true` did not recurse and always answered `recursion_depth: 0`. The
spec says servers SHOULD traverse at least 3 levels, MAY do more, and MUST not recurse without end. The walk runs under
`runtime.mutex` over a graph a client builds.

## Decision Outcome

- Depth is fixed at 3 levels, the first being the direct relations; the spec's minimum and no more.
- Beyond the first level the walk is offered at most 2048 relation-bearing events in total. The first level is as
  unbounded as before (linear in the room's events, from the one pass that finds the room's relations).
- `recursion_depth` is the number of levels completed: 3 when all three were examined (including when a level had
  nothing to walk from, since nothing deeper could be missed), fewer when the 2048 cap stopped the walk, and 1 when
  `recurse=false` was supplied. It is absent when `recurse` was not supplied.
- The walk continues only through events that match the `rel_type` and `event_type` filters and that the viewer may see
  (`HistoryVisibility`), which is what the spec's "only relation ... through a non-matching intermediate event, will
  not be included" requires and also means an event the viewer cannot read is never a path to one they can.

Rejected: reporting the maximum depth only when events were found at it. A client reading 2 for a graph that ended at
level 2 would think deeper events might exist.
