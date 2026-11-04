# Bundled aggregations are built from a relation index kept inside the event table

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

The Client-Server API says an event served through `/messages`, `/context`, `/event`, `/relations`,
`/sync` (a `limited` section), `/search` and `/threads` carries `unsigned.m.relations` when it has
children that can be aggregated ("Aggregations of child events"). Only `/threads` did, and it found the
children by walking the room's newest events. Every other endpoint serves events under
`runtime.mutex`, one event at a time, so finding an event's children by scanning `store.events` would
make a page of N events cost N scans of the table. How do the endpoints find the children, and who
builds the aggregate?

## Decision Drivers

* A served event costs a bounded amount of work however large the table is.
* Every writer of `store.events` (store, hydration, room reload, status change, redaction, erase) must keep the
  index right without each caller remembering to.
* A redacted child "breaks the relationship" and must leave the aggregate at once.
* `unsigned` is built by the server and never passed through (ADR-0402).
* Schema and migrations are not touched.

## Considered Options

* A relation index inside `database::EventTable`, rebuilt from the rows, and one `sync::BundledAggregations`
  that every endpoint calls.
* A separate index on `PersistentStore`, updated by the functions that write events.
* A per-endpoint walk of the room's events (what `/threads` did).
* A new table of relations.

## Decision Outcome

Chosen option: "a relation index inside `EventTable`", because the table already owns every row and every
other index over them, so `insert`, `insert_all`, `erase_if`, `modify`, `extract` and `clear` keep it current
by construction, and a writer that bypasses them does not compile. `modify` recomputes a row's relation
key, so a redaction (the redacted JSON has no `content."m.relates_to"`) removes the child from the
index in the same call that rewrites its JSON. The index is derived from the JSON and rebuilt at
hydration and `reload_room` with no schema change.

Rules the code depends on, which are not obvious locally:

* The index lists every row with a usable `content."m.relates_to"` (string `event_id` of 1 to 255 bytes and a
  `rel_type` of `m.replace`, `m.thread` or `m.reference`), whatever its status or room, in one list per kind under
  the target. `m.annotation` and any other `rel_type` are not indexed: the builder never aggregates them, so they
  would only cost memory and window. Status and room are judged when the child is read, because
  status changes after insertion and the target is client-chosen text. A row without the substring
  `"m.relates_to"` is not parsed.
* `sync::BundledAggregations` is the only builder. It counts a child only if it is in the parent's room,
  not rejected or soft-failed, not from an ignored sender and visible to the viewer through
  `HistoryVisibility`. A stored `unsigned.m.relations` is never passed through.
* Work per served event is capped, and each kind has a window of its own: `max_aggregated_children_examined`
  index entries per kind (newest first), `max_aggregated_edits_parsed` candidate edits parsed,
  `max_reference_chunk_entries` references. A long thread or a run of references therefore never pushes an
  edit out of the bundle. Past the cap `count` and `chunk` describe the newest children. What remains: a flood
  of `m.replace` relations on one target (from strangers, whose edits are invalid but are listed all the same)
  can still push the real edit out of the `m.replace` window; `/relations` still lists it.
* `m.thread` `latest_event` is the child with the greatest `(depth, stream_ordering)`, so a backfilled
  older reply stored later is not the latest. `/threads` uses the same rule.
* `m.replace` follows "Validity of replacement events": same sender, same `type`, no `state_key`, an
  `m.new_content` (not required of `m.room.encrypted`, whose payload the server cannot read), the original
  not itself an edit and not redacted. The newest by `origin_server_ts`, then the largest event ID, that the
  viewer may see wins.
* Sliding sync (MSC4186, no text on aggregations) follows classic `/sync`: a room whose `timeline` is
  `limited` carries aggregations, one that is not does not.

### Negative Consequences

* Memory grows by one position per relating event of an aggregated kind, and an insert or status change of such an event parses
  its JSON once.
* A table class now depends on the canonical JSON parser.

## Links

* Builds on [ADR-0215](0215-the-event-table-indexes-by-id-and-by-stream-order-through-positions.md),
  [ADR-0300](0300-the-event-table-keeps-a-room-and-time-index.md) and
  [ADR-0402](0402-unsigned-is-built-from-what-the-server-computes-never-stored-from-a-remote-pdu.md)
