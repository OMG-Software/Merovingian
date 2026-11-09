# Room aliases are indexed in a table class and capped per user and per room

* Status: accepted
* Deciders: project owner
* Date: 2026-11-09

Technical Story: security audit run 4, finding F-03

## Context and Problem Statement

`PersistentStore::room_aliases` was a `std::vector` with no cap and no index. `find_room_alias`, the existence check, delete
and reassign scanned it, and `GET /rooms/{roomId}/aliases` and `appservice_room_aliases` (called per event) looped over
all of it under `runtime.mutex`. `PUT /directory/room/{roomAlias}` and `POST /createRoom` inserted with no count check, so one
account could create hundreds of thousands of aliases and make every listing hold the global lock for hundreds of
milliseconds. How are the table cost and its size bounded?

## Decision Drivers

* Work under the runtime lock must not grow faster than linearly with client-controlled input.
* Bridges legitimately own many aliases.
* The Matrix specification defines neither a limit nor pagination for the aliases listing.

## Considered Options

* Index the table and cap new aliases per user and per room.
* Index the table only, with no cap.
* Cap only, and keep scanning.
* Paginate `GET /rooms/{roomId}/aliases`.

## Decision Outcome

Chosen option: "Index the table and cap new aliases per user and per room".

* `database::RoomAliasTable` owns the rows (the shape of ADR-0325) and keeps hash indexes by alias, by room and a count per
  creator. A delete or reassign finds its row by hash and fixes positions up (swap-and-pop), so no operation scans the
  table, and a writer that bypasses the class does not compile. Indexes hold positions, so the defaulted copy of the store
  keeps them valid (ADR-0523).
* `server.client_api.max_room_aliases_per_user` and `max_room_aliases_per_room` (default 100 each, 1..100000) refuse a
  NEW alias with `400 M_TOO_LARGE`, the project code for per-user caps (ADR-0173), writing nothing. The check follows the
  validity, domain, power, appservice-exclusivity and already-exists answers, so existing error precedence is unchanged:
  an alias that exists keeps its `200` or `409` at the cap. `POST /createRoom` with `room_alias_name` counts toward the
  per-user cap and is refused before the room is made.
* A request authenticated as an application service (as_token or masquerade) is exempt from the per-user cap only. The
  per-room cap still binds it, so one room listing stays bounded.
* `reassign_room_alias` during room upgrade is not capped: it moves at most one room of aliases into a fresh room.

### Positive Consequences

* Lookups, a room listing and the per-creator count cost the keys involved, not the table.
* A room alias list, and so each listing request, is bounded by the per-room cap for every caller.

### Negative Consequences

* A user at the cap must delete an alias before creating another; an operator can raise the caps.
* The per-user count is by `creator_user_id`; legacy rows with an empty creator are charged to nobody.

## Pros and Cons of the Options

### Index only, with no cap

* Good, because nothing is refused.
* Bad, because the table, memory and the listing response still grow without bound, and one room listing would be
  arbitrarily large under the lock.

### Cap only, and keep scanning

* Good, because it is a smaller change.
* Bad, because every lookup still scans the whole table, and the table is bounded only per user, so many users together
  keep it large.

### Paginate the aliases listing

* Good, because it bounds one response.
* Bad, because the specification defines no pagination for `getLocalAliases`, so clients would not use it, and the full
  listing would still be built under the lock.

## Links

* Follows [ADR-0325](0325-the-state-group-tables-own-their-rows-and-index-them.md)
* Follows [ADR-0173](0173-cap-global-account-data-types-per-user.md)
* Follows [ADR-0523](0523-persistent-store-copies-are-defaulted.md)
