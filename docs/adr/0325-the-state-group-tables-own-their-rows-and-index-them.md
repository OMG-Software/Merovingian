# The state-group tables own their rows and index them by key

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-07 and F-15 (per-request and per-PDU work under `runtime.mutex` scanned the
server's whole state-group tables)

## Context and Problem Statement

`PersistentStore::state_groups`, `state_group_state` and `event_state_groups` were plain `std::vector`s holding every
room's rows. `find_event_state_group` and `find_persistent_state_group` were `find_if` over them, and
`read_state_group_full_state` scanned all of `state_group_state` once per hop of a delta chain of up to 101 groups.
Every ingested PDU, every local send and every federation read of a room's events paid that, under `runtime.mutex`, for
rows of rooms the request had nothing to do with. `ServerEventFilter` and `sync::HistoryVisibility` built hash maps over
the same three tables on every request, so each paid the server's size too.

How should a lookup by event ID, group ID or group-with-its-entries cost the key's rows, without any writer being able to
leave the answer stale?

## Decision Drivers

* Work under `runtime.mutex` must stay bounded by the request (`src/homeserver/AGENTS.md`).
* There are several writers: `apply_state_group`, `apply_event_state_group`, both backends' hydration and `reload_room`.
  A missed one gives wrong state silently, which is worse than slow.
* ADR-0215 and ADR-0300 solved the same problem for `events`.
* The federation worker reads its snapshot without the lock today (F-27 changes that), so the answer must not be a
  structure that is more fragile to read than the vectors it replaces.

## Considered Options

1. Keep the vectors public and put side indexes beside them, trusted while a row count matches (the `client_txn_*` and
   `key_signature_*` pattern).
2. A table class per vector, as `EventTable` is: it owns the rows, exposes them read-only, and every change goes through
   its own methods, which keep a hash index of positions in step.
3. Move the lookups into SQL, or add a schema index and read the database per lookup.

## Decision Outcome

Chosen option: 2. `StateGroupTable` (by `state_group_id`), `StateGroupEntryTable` (a group's entries by
`state_group_id`) and `EventStateGroupTable` (`event_id` to group) in `database/state_group_tables.hpp`. The members keep
their names and still iterate like the vectors, so a reader that walks a whole table still compiles; a writer that calls
`push_back`, `erase` or assigns an element does not. That is how every writer was found: the compiler listed them, and
each now calls `insert`, `insert_all`, `assign` or `erase_if`. Hydration and `reload_room` go through `insert_all` /
`erase_if` as `EventTable` does, and `erase_if` renumbers the positions in one pass without rehashing the keys.

The indexes hold positions, never iterators or pointers. A group ID and an event ID are held at most once (their
primary keys on disk); a second group row with a held ID keeps the first, as the `find_if` it replaces did.

Lookups are `store.event_state_groups.state_group_of(event_id)`, `store.state_groups.find(id)` and
`store.state_group_state.entries_of(id)`; `database::find_event_state_group`, `find_state_group` and
`read_state_group_full_state` use them, so a chain read costs the rows of the groups on the chain.
`ServerEventFilter` and `HistoryVisibility` keep only their per-request verdict cache and build no map of their own.
`make_store_event_lookup` calls `EventTable::find` and builds nothing per resolution.

Option 1 was rejected: `client_txn_ids` shows what it costs. A row pushed directly leaves the count unequal, and every
lookup falls back to the scan it was added to avoid, silently. Here that fallback would be the audited defect. Option 3
was rejected: it adds a database read under the lock for data that is already resident, and the schema is frozen
(ADR-0224); no schema changed.

### Reader discipline

A table has no lock; like `EventTable` it is guarded by whatever guards its store (`runtime.mutex` in main). A write can
reallocate a row vector and rehash an index, and `reload_room` changes the three tables one after another. A reader
therefore needs exclusion from writers exactly as it did for the vectors: the index makes a torn read no safer or less
safe than before, and it makes the index part of what must be excluded. A `std::string_view` or view returned by a table
is valid until the next write to that table. The federation worker's lock-free snapshot reads (F-27) must take the
exclusion this adds nothing to, not rely on the index.

### Positive Consequences

* Event-to-group, group and group-entries lookups are O(1) plus the rows returned.
* Federation `event`, `backfill`, `get_missing_events` and `timestamp_to_event`, client history-visibility reads, state
  before an event and local compose no longer pay for unrelated rooms' state groups.

### Negative Consequences

* Memory: one hash entry per event mapping, group and distinct group with entries, on top of the rows.
* `reload_room` and hydration do a hash insert per row.

## Links

* Refines [ADR-0215](0215-the-event-table-indexes-by-id-and-by-stream-order-through-positions.md) and
  [ADR-0300](0300-the-event-table-keeps-a-room-and-time-index.md)
* Corrects the cost note in [ADR-0282](0282-redact-never-drop-events-a-requesting-server-could-not-see.md): the filter no
  longer builds the state-group indexes per request.
