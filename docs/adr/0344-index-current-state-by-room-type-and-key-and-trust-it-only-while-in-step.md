# Index current state by room, type and key, and trust the index only while it is in step

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-32 (`homeserver.space-hierarchy-walk-quadratic-state-scans-under-runtime-mutex`)
and F-10 (`cs.members-current-roster-quadratic-state-backed-member-find-under-runtime-mutex`)

## Context and Problem Statement

`PersistentStore::state` is a plain `std::vector<PersistentStateEvent>` with one row for each current state event of every
room. `space_hierarchy.cpp` read it through a helper that scanned the whole vector for each of a child's content,
timestamp and sender, so a space with k children cost 3k scans of the server's state, and `/members` walked the whole
vector to find one room's member rows. All of it ran under `runtime.mutex`. How should state be read by key and by room
without scanning, given that about forty readers and many tests use the vector directly?

## Decision Drivers

* ADR-0215's table is a class that owns its rows; `state` is not, and tests push, erase and remove rows from the vector
  directly.
* Every writer must be accounted for, including hydration and `reload_room` (a federation worker's snapshot).
* A missed writer must cost speed, never a wrong answer.

## Considered Options

* Keep the vector and add indexes of positions beside it, valid only while their row count equals the vector's
* Replace the vector with a `StateTable` class like `EventTable`
* Scan, but once per request instead of once per lookup

## Decision Outcome

Chosen option: "positions beside the vector", following `key_signature_target_index` (CSAZ-10).

* `state_position_index` maps `(room_id, event_type, state_key)` to a position in `state`, and `state_room_index` maps a
  room to the positions of its rows. `state_indexed_rows` records the vector size they were built for.
* `find_current_state_event_id` and `for_each_room_state_row` use the indexes only while `state_indexed_rows ==
  state.size()`, and check that the row a position names still has the key asked for. Otherwise they scan the vector.
  A row appended behind the store's back therefore makes lookups scan until `rebuild_state_index`.
* The writers are `apply_current_state` (also used by `store_state`) and the in-memory update in
  `store_event_with_state`, which append through `note_state_row_appended`; `reload_room`, which erases a room's rows and
  appends the snapshot's, and both hydration paths (SQLite, PostgreSQL), which call `rebuild_state_index`. Replacing a
  row's `event_id` in place keeps its position and needs no index change.
* `space_hierarchy.cpp` reads each state event once through the index, and `space_children` walks the space's own rows
  and parses each child event once. `/members` walks the room's own state rows.

### Positive Consequences

* A state read by key is a hash lookup and a read of one room's state touches only its rows.
* Tests that edit `state` directly keep working, from a scan.

### Negative Consequences

* A caller that erases one row and appends another to the vector directly, leaving the size unchanged, can leave a stale
  index: a hit is checked against the row, but an absent key is believed. Production code does not edit the vector
  outside the writers above. Any new writer must call `note_state_row_appended` or `rebuild_state_index`.
* `store_state` and `store_event_with_state` still find the existing row with a scan before they write.

## Pros and Cons of the Options

### A `StateTable` class

* Good, because the indexes would be consistent by construction.
* Bad, because it changes about forty readers and hundreds of test lines for a finding about three endpoints.

### Scan once per request

* Good, because it needs no index.
* Bad, because a space's links are k keys of one room; the scan is still the size of the server's state per request.
