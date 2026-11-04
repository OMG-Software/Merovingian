# `events` and `state_groups` are indexed by `room_id`; `stream_ordering` is not indexed

* Status: accepted
* Date: 2026-11-04

Technical Story: November analysis P12.

## Context and Problem Statement

The analysis found no index on `events.room_id` or `events.stream_ordering`.

## Decision Outcome

The queries that run against the database were read, not guessed. A cold room is reloaded with `WHERE room_id = ?`
against `events` and `state_groups`, and six relation tables are joined to `events` with `ev.room_id = ?`, which
walk `events` by room. `membership`, `invites`, `current_state`, `receipts` and `forward_extremities` already lead
their primary key with `room_id`. So v1 gains `idx_events_room_id` and `idx_state_groups_room_id`.

`stream_ordering` gets no index. No SQL statement filters or orders `events` by it: the table is loaded whole at start
and ordered in memory (`EventTable`). The column is `TEXT` (every numeric column is), so an index would order
`'10'` before `'9'` and could not serve a numeric range anyway. If a query ever needs it, the column's type has to be
decided first.

The indexes are in `core_indexes` and `migrations/001_initial_schema.sql` together (no upgrade shims before 1.0).

## Consequences

* Do not add an index on `stream_ordering` while it is `TEXT`.
