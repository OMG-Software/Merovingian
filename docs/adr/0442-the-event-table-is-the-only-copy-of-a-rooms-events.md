# The event table is the only copy of a room's events

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-04

Technical Story: Performance defect P6, quadratic start-up and a second copy of every event's JSON.

## Context and Problem Statement

`LocalRoom::events` held the signed JSON of every event a room had stored, beside the same JSON in `EventTable`.
Start-up filled it with a `find_if` over all rooms for every event, and found each membership's room and its place in
`room->members` with scans, O(events x rooms + sum of members^2). Its only readers were a smoke-test summary and
the cosigned-invite path that kept it in step; it was not a source of truth (ADR-0342 already forbids reading IDs
from it), and a redaction or a reload updated the table and not the copy.

## Decision Outcome

`LocalRoom::events` is removed. A room's events are read from `PersistentStore::events`, so a redacted event is
served as the redacted JSON and a reloaded room reads what the reload wrote. Start-up builds the roster with a
room ID map and a set of (room, user) pairs local to start-up. ADR-0342's rule stands in a stronger form: there is no
list of event JSON on a room to read an ID from.

`event_edges`, `event_auth` and `event_signatures` are left as they are: flat mirrors of the relation tables that
hydration folds into each `PersistentEvent`, and which many tests read; removing them is a separate change.

## Considered Options

* Keep the copy and fix start-up only. Rejected: it keeps a second, drift-prone copy of the largest data in memory.

## Links

* Refines [ADR-0342](0342-an-upgrade-names-the-old-rooms-last-event-by-its-forward-extremity.md)
