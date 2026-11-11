# Unread counts and read markers read a bounded number of the newest rows

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, classic sync's unread count and read markers read a room's whole history

## Context and Problem Statement

`count_unread_by_thread` and `read_markers_for` walked all of a room's rows for every room of every `/sync`, and
`PushRuleUnreadClassifier::counted_after` walked the whole event table once per request to find when the user joined.

## Decision Drivers

* The work under `runtime.mutex` must not grow with what a remote server chooses.
* An unread count is a number on a badge. It need not be exact past what anyone reads.

## Considered Options

* Stop at the read marker and the start of the join, with no other bound
* Stop there and read at most a fixed number of rows
* Keep a per-user counter updated on every event

## Decision Outcome

Chosen option: "Stop there and read at most a fixed number of rows".

`count_unread_by_thread` walks newest first down to the later of the unthreaded marker and the join, at most
`sync::max_unread_rows_examined` (1000) rows. `read_markers_for` reads the user's own events the same way. The two stay
consistent: an own event older than the newest 1000 rows could only mark rows the count does not read. The start of the
join comes from the user's member events, from the current one back through the recorded state transitions, with the
same budget, as `HistoryVisibility::membership_timeline` already walks them. A room with no current member row for the
user falls back to its newest rows.

### Rejected: no budget

A user who never sends a receipt in a room with a long history has no marker, so the walk would still read everything
since the join. A remote server can make that history as long as it likes.

### Rejected: a stored counter

Every writer of an event, receipt, membership or push rule would have to keep it right for every local member of the
room, and a push rule change alters every past event's answer.

### Negative Consequences

* A room with more than 1000 rows since the marker reports a lower bound, as the push badge does (ADR-0207). It never
  counts an event a full count would not.
* `GET /notifications` `read` uses the same markers: a very old notification the user's own later event covered, with
  more than 1000 rows since, can report `read: false`.
