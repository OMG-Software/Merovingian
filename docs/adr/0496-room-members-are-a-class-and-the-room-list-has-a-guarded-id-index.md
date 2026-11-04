# `LocalRoom::members` is a class with a hash set, and `LocalDatabase::rooms` has a guarded position index

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`joined(room, user)` and `room_has_member` scanned `LocalRoom::members`, and `find_room` scanned `LocalDatabase::rooms`, on
every request that names a room and on every `/sync` and `/joined_rooms` (which call `joined` for each local room). Under
`runtime.mutex` that is the number of rooms for `find_room`, and for a user in none of them, every member of every room for
`joined`. Both vectors are public and are written directly by hydration and by many tests.

## Decision Outcome

* `LocalRoom::members` is a `RoomMembers` (`room_members.hpp`): the ordered vector and a hash set of the same members.
  The only writes are its methods (`add`, `remove`, the `push_back`/`emplace_back` forms that call `add`), so a write that
  skips the set does not compile. Order is the order of joining, as before; `values()` and the conversion to
  `std::vector<std::string> const&` expose it read-only to code that iterates it or hands it to the appservice module.
  `contains` is one hash lookup.
* `LocalDatabase::rooms` stays a plain vector, because hydration and tests write it directly. `find_room` and
  `find_local_room` use an id-to-position map in the manner of ADR-0344: it is rebuilt when its row count differs from
  `rooms.size()`, a hit is verified against `rooms[pos].room_id`, and a miss or a mismatch is settled by a scan that
  rebuilds the map when it finds the room. A hit costs one lookup; only a miss costs a scan, and a stale map can therefore
  never answer "no such room" or return another room. The first room of a given ID wins, as in the scan this replaces.
  Pointers into `rooms` are as valid as before (the vector is not changed by a lookup).
* The map is `mutable` and is written from const lookups. That is safe only because every reader holds `runtime.mutex`,
  which is one recursive `std::recursive_mutex` taken exclusively (no `shared_lock` or `shared_mutex` guards runtime
  state; the federation worker's `store_read_guard` guards a separate process's own store). A new reader of
  `LocalDatabase` takes that mutex.

## Rejected

* A `RoomList` class replacing the vector: hydration and tests construct and edit `rooms` in dozens of places, and a
  wrapper would change all of them for the same effect.
* A bare map with no verification: a test that erases one room and adds another keeps the size and would answer for the
  wrong room, and a stale answer here decides membership and access.
* An index of user to rooms: it must follow every membership write path, which `RoomMembers` already is.
