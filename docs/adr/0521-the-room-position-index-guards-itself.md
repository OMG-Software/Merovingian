# The room position index guards itself

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

Technical Story: SonarQube Cloud rule `cpp:S8379` on `LocalDatabase::room_position_index` and `room_indexed_rows`.

## Context and Problem Statement

[ADR-0496](0496-room-members-are-a-class-and-the-room-list-has-a-guarded-id-index.md) added an index from room ID to
position in `LocalDatabase::rooms`. It lived as two public `mutable` fields of `LocalDatabase`, written by `const`
lookups and guarded only by every caller holding `runtime.mutex`. That guard is a comment the compiler cannot check,
and a new caller that looked a room up without `runtime.mutex` would race on the map. How should the index be guarded?

## Considered Options

* Keep the `mutable` fields, guarded by `runtime.mutex`.
* Move the cache into its own class with its own mutex.

## Decision Outcome

Chosen option: "Move the cache into its own class with its own mutex": `homeserver::RoomPositionIndex` holds the map,
the indexed row count and a `std::mutex`, and exposes one `const` method, `find(rooms, room_id)`, that locks, applies
the ADR-0496 rule (trust a position only while the indexed row count equals `rooms.size()` and the room there carries
the requested ID; otherwise scan and rebuild) and returns the position.

Copying or moving an index yields an empty one: it is a cache that rebuilds on demand, and the position of a room in
another vector means nothing here. Copy operations are deleted. Move construction is `noexcept` because a
default-constructed map does not throw (asserted). Move assignment is `noexcept` and clears the target without locking,
which is safe only because no other thread may use an object while it is assigned to; `LocalDatabase` is only ever
moved while it is private to one thread.

The extra lock is uncontended, since every caller already holds `runtime.mutex`. The index still does not guard
`rooms` itself: a caller must still not edit `rooms` while another thread reads it.

## Pros and Cons of the Options

### Keep the mutable fields

* Good, because it is correct today and has no extra lock.
* Bad, because the guard is a comment, and a caller without `runtime.mutex` would race.

### Own class with its own mutex

* Good, because the compiler enforces the guard on the cache's members.
* Good, because `LocalDatabase` no longer has public `mutable` fields.
* Bad, because of one uncontended lock per lookup.
