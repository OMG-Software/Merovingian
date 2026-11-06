# The greatest `origin_server_ts` of a room's events is kept in the event table

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

A sliding sync room's `timestamp` is the greatest `origin_server_ts` of the room's events, whatever their status.
`latest_timestamp` parsed the JSON of every event of the room for every room built, which is the whole history of every
listed room per response, under `runtime.mutex` (ADR-0494 left it open).

## Decision Outcome

`EventTable` keeps, per room, the greatest positive `origin_server_ts` of the rows it holds (`room_latest_origin_server_ts`,
0 for a room with none). Row JSON is read with the allocation-free top-level scan the time index already uses.

* `insert` and `insert_all` (hydration, room reload) raise the room's value as each row is added.
* `erase_if` and `modify` recompute the value of each room that lost a row, or whose row changed room or timestamp, from
  that room's rows (O(the room), only on those writes). A redaction keeps `origin_server_ts`, so it does not trigger it.
* `clear` and `extract` empty it.

The value equals the one the parse gave: every status counts (unlike the time index, which skips outliers, rejected and
soft-failed rows), and a row with no positive integer member of its own JSON counts as nothing.

## Rejected

* Computing it on first read: the table is read through `const` references under `runtime.mutex`, so a lazily written member
  would make every reader a writer.
* A column in the database: the value is derived from the JSON, so it would need a migration and a way to keep it in step.

## Consequences

The value is a property of the room, not of the viewer. A sliding sync room is built only for a room the user has joined
(the room list lists joined rooms, a subscription needs a join, an invite gets stripped state alone), so a user who has left
is never given it; while joined they are given the greatest timestamp of the room's events, those from before they joined
and after they leave included, as before this change.
