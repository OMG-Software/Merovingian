# The event table owns its rows and indexes them by event ID and by stream order through positions

* Status: accepted
* Date: 2026-10-22

Technical Story: follow-up deferred from PR #523 (conformance audit wave 5, ADR-0207)

## Context and Problem Statement

`PersistentStore::events`, the in-memory mirror of the `events` table, was a plain
`std::vector<PersistentEvent>`. Every lookup by event ID was a linear `find_if` over every stored
event (about forty call sites, including `sync::event_thread_id`, which makes up to three of them
per event it classifies), all under `runtime.mutex`. The vector was also not in stream order:
hydration selects with no `ORDER BY` (SQLite) or in event-ID order (PostgreSQL), PostgreSQL moves a
row whose status is updated, and stream orderings are allocated before commit, so events in
different rooms commit out of order. A walk that wants the newest events first, such as the push
badge's capped unread count (ADR-0207), could not stop early and had to charge every lookup to a
row budget.

How should the store find an event by ID, and visit events in stream order, without either
answer going stale when a writer adds, updates, redacts or removes a row?

## Decision Drivers

* Work under `runtime.mutex` must stay linear in what a request controls (`src/homeserver/AGENTS.md`).
* Every writer must keep both indexes right; there are a dozen in `src/` and over a hundred
  `push_back` calls in test fixtures.
* Indexes must survive the row vector reallocating.
* Existing readers that iterate the events, look one up, or count them should not all have to change.

## Considered Options

1. Keep the vector public and add side indexes beside it, trusted only while a row count matches
   (the CSAZ-10 `key_signature_target_index` pattern).
2. Wrap the rows in an `EventTable` that keeps the vector sorted by stream ordering, plus an
   event-ID → position map.
3. Wrap the rows in an `EventTable` that keeps them in arrival order, plus an event-ID → position
   map and a separate stream-order index: a vector of positions sorted by
   `(stream_ordering, position)`.

## Decision Outcome

Chosen option: 3, a separate ordered index inside a class that owns the rows.

The class (`include/merovingian/database/event_table.hpp`) exposes the rows read-only. Iterating it
still visits arrival order, `find()` and `contains()` use the ID map, and `in_stream_order()` walks
the order index (reverse it for newest first). Changes go only through `insert()` / `push_back()`,
`insert_all()`, `erase_if()`, `modify()`, `extract()` and `clear()`. `modify()` puts back
`event_id` and `stream_ordering` if a mutation changes them, so a row cannot be renamed or moved in
stream order in place. Because the type allows nothing else, a writer that bypasses the indexes
does not compile. That is how every writer was found.

Both indexes hold positions, never iterators or pointers. An event ID is held at most once (it is
the table's primary key on disk). Equal stream orderings keep arrival order. Hydration and room
reload use `insert_all()`, which sorts the new rows' positions once and merges them into the order
index, instead of shifting it once per row. `erase_if()` renumbers both indexes in one linear pass
without rehashing the remaining IDs.

Option 2 was rejected. A sorted vector looks simpler and gives every existing loop stream order for
free. But an event that commits behind a newer one has to be inserted mid-vector. That moves every
later `PersistentEvent` (several strings and vectors each) and changes all their positions, so the
ID map must be rewritten for each row it moved: hash updates proportional to the distance from the
end, under `runtime.mutex`. It would also silently change the iteration order every existing reader
sees. With option 3 the rows never move on insert. A late commit shifts only 8-byte positions in
the order index, and the ID map is untouched.

Option 1 was rejected because a count check notices an append but not a removal followed by an
append, nor an in-place change to `event_id` or `stream_ordering`. It would serve stale positions
or quietly fall back to scans.

### Positive Consequences

* Event lookups by ID cost a hash probe instead of a scan of every stored event.
* A newest-first walk sees true stream order whatever the hydration or commit order. The push badge
  count can stop early (ADR-0207 follow-up).
* Existing readers kept compiling: the table is a sized, random-access range with
  `size()`, `empty()`, `operator[]`, `front()`, `back()` and `rows()`.

### Negative Consequences

* A stream-order walk goes through one indirection per row (less cache-friendly than a sorted vector).
* The ID map stores each event ID a second time.
* `modify()` copies the row's event ID to check it afterwards. It is used for status updates,
  redactions and relation reconstruction, never per request row.

## Rules for future code

* Look events up with `store.events.find()` / `contains()`, never `find_if` over `store.events`.
* Walk events in stream order with `store.events.in_stream_order()`. Do not assume iteration order
  of the table means anything.
* Add many events at once with `insert_all()`, not one `insert()` per row.
