# A worker's room reload carries the room's state groups

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestJumpToDateEndpoint/parallel/federation/*`

## Context and Problem Statement

The federation worker's store is a snapshot taken at start-up; `room_sync` makes it re-read one room
with `database::reload_room`. Federation reads (`/timestamp_to_event`, `/backfill`,
`/get_missing_events`, `/event`) judge an event through `ServerEventFilter`, which looks up the state
group recorded for the event and fails closed when there is none (ADR-0064). `reload_room` re-read the
room's events and current state but not its state groups, so every event created after the worker
started looked invisible to other servers: `timestamp_to_event` answered 404 and `/backfill` sent those
events redacted.

## Considered Options

* Carry the room's state groups, their entries and its events' group mappings in `RoomReloadSnapshot`
* Relay these reads to main, which holds the groups
* Treat an event with no recorded group as visible in the worker

## Decision Outcome

Chosen option: "Carry the room's state groups … in `RoomReloadSnapshot`", read in the same read
transaction as the events (ADR-0161), and replacing only that room's rows. It keeps the worker serving
reads itself without weakening the fail-closed visibility check. Relaying would move hostile read traffic
into main; opening the check would serve history a requesting server may not see.

### Positive Consequences

* An event created after the worker started is judged on its real state group.

### Negative Consequences

* A reload reads three more tables. A table a worker-served read comes to depend on must be added to
  the snapshot and to `reload_room` too, or the same failure returns for it.

## Links

* Refines [ADR-0161](0161-room-reloads-read-one-snapshot-the-whole-store-load-does-not.md)
* Related to [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
