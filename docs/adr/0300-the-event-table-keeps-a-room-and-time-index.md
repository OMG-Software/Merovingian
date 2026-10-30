# The event table keeps a per-room index by origin_server_ts

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement run 13 (`timestamp_to_event`, ADR-0299)

## Context and Problem Statement

`timestamp_to_event` must find the event nearest a timestamp in one room under `runtime.mutex` (the client
endpoint) or `runtime.mutex` taken by the provider (the federation endpoint, in main and in the federation
worker). `origin_server_ts` exists only inside each event's JSON; the `events` table has no column for it and
the in-memory `EventTable` (ADR-0215) had no order but stream order. A scan of every event per request is
unbounded work under the lock, driven by a client or a remote server (src/homeserver/AGENTS.md, "Work under
the runtime lock is bounded by the request").

## Decision Outcome

`EventTable` keeps a third index, with the other two and maintained by the same writers, so no caller can
forget it: per room, a vector of (`origin_server_ts`, `depth`, `stream_ordering`, position) sorted by that key.
`nearest_by_time` seeks it with a binary search and steps from there, offering at most
`max_time_search_examined` rows to a caller-supplied filter, so a lookup costs O(log n + 1000) however large
the room.

* No migration. The timestamp is parsed once, when a row enters the table (`insert`, `insert_all`), by a
  single-pass scanner that reads the top-level member only (a member of the same name in `content` or
  `unsigned` is never taken), and it is rebuilt by hydration like the other two indexes.
* A row is indexed only while it is a timeline event: status not `outlier`, `rejected` or `soft_failed`
  (the statuses clients are never shown; an owner decision named outliers and rejected, soft-failed is added
  because clients are never shown those either), with an integer top-level `origin_server_ts`.
* `modify` takes the key before and after the mutation and moves the row in or out when the room, depth, status
  or JSON changed, so promoting an outlier or rejecting an event keeps the index right. Redaction keeps
  `origin_server_ts`, so it never moves a row.
* `erase_if` renumbers positions in every room's vector; `insert_all` appends and merges per touched room
  instead of one shift per row.

## Considered Options

* A migration adding an indexed integer column. Rejected: the in-memory table is what requests read, so a
  column would still need an in-memory structure, and the owner chose no migration (migrations collapse at
  1.0, ADR-0216).
* A bounded scan of the room's rows. Rejected: bounded only by a cap that would make "not found" wrong for old
  timestamps in a big room.
* A tree (`std::set`) per room. Rejected: one node allocation per event for what a sorted vector does with a
  shift that is almost always zero (a new event is nearly always the room's newest).

## Consequences

* Memory: 32 bytes per timeline event on top of the row.
* An event whose JSON has no integer `origin_server_ts` (only test fixtures) is not findable by time.
* A new writer needs nothing: the table is the only place rows are added, replaced or removed.
