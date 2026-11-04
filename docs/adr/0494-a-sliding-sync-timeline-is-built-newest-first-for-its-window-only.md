# A sliding sync room's timeline is built newest first, for its window and one more event only

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`build_room_response` walked every event of the room oldest first, ran the visibility, ignore and serialisation work on each
one that passed the delta floor, and then dropped all but the newest `timeline_limit`. For an initial room that is the whole
history, serialised and thrown away, under `runtime.mutex`, per room per response.

## Decision Outcome

The room's events are walked newest first (`room_in_stream_order | views::reverse`) and the walk stops once `timeline_limit + 1`
events have been built. The extra event is what makes the timeline `limited` and positions `prev_batch`; the kept window is
the newest `timeline_limit` of those, put back in stream order. The result is the same as building every event and dropping
the oldest, because the filters are per event and do not depend on their neighbours.

* A new filter in that walk must stay a per-event test. A rule that looks at the events around one (a gap, a count) cannot
  be placed there without changing the walk.
* An event is parsed to classify it for the ignore list only when its sender is ignored (ADR-0436 applies here too).
* The member counts, heroes and required state of a room are read from the room's own membership and state rows
  (ADR-0437, ADR-0344), not from a scan of every room's.

## Update (same day, after review)

* The walk also ends at the delta floor: it is newest first and `room_in_stream_order` is ascending in `stream_ordering`
  (rows of equal ordering in the order added), so once a row is at or below `room_since_event_ordering` every row after it
  is. That is a `break`, not a `continue`; an incremental build of a room with nothing new no longer walks the room.
* `latest_timestamp` is no longer open: the event table keeps the room's greatest `origin_server_ts` (ADR-0497).
* The room list (`compute_room_list`) found a user's joined rooms with a scan of every membership row per room; it now visits
  each room's own rows (ADR-0437).
