# A sliding sync request learns the caller's rooms once, and every list reads that

* Status: Accepted
* Date: 2026-11-12

Technical Story: security audit run 3, finding C07

## Context and Problem Statement

For each list, `compute_room_list` tested every joined room against the list's filters and sort keys, and several of the
tests scanned a server-wide table: `is_invite` every membership row, `is_encrypted` and `room_types` every current-state
row, `is_dm` parsed the caller's whole `m.direct` for each room, and `by_notification_count` read every stored receipt, once
per joined room, for up to 32 lists, under `runtime.mutex`. An account that creates rooms raises both the number of
joined rooms and the size of the tables. ADR-0172 bounded the sort comparator and named this cost as left over.

## Considered Options

* A `SlidingSyncRequestLookups` built once per request and passed to every list and every room built.
* A new index of receipts by room and user in the store.
* Cache each answer on the connection between requests.

## Decision Outcome

Chosen option: "a lookups object built once per request", because the request is the unit that has both the lock and
the cost, and nothing it holds can go stale or need maintaining by a writer.

* The joined rooms and the invites come from the user's own membership rows (`for_each_user_membership_row`,
  ADR-0609), checked against the room records once; `is_encrypted` and `room_type` use the room's current state by its
  index (`find_current_state_event_id`, ADR-0344); `m.direct` is parsed once into a set; a room's `m.tag` once per room.
* The user's `m.read` and `m.read.private` receipts are collected in one pass over the receipts table and grouped by
  room, and each room's `ReadMarkers` is computed from its own group, once. The same object serves
  `build_room_response`, so the rooms a response builds share the pass.
* The lookups are filled through non-const functions, never `mutable` (ADR-0525); a request owns one on its thread under
  the lock.
* A room's windowed membership of each list is held in a hash set while the response's per-room config is combined, so
  asking which lists hold a room is a lookup, not a scan of a window that a client-chosen range can make as long as the
  user's room list.

### Rejected: an index of receipts by room and user

Another workstream adds one for classic sync. A second index in this area would need to be correct on every writer
and on load, to save a single pass per request that the lookups already make. This one pass per request is the work
bound the brief asks for.

### Rejected: caching answers on the connection

A cached `is_encrypted` or room type is wrong the moment the room's state changes, and the connection cannot see that.

## Consequences

* One request now costs one pass over the receipts table (the table, not the rooms times it), one pass over the room
  records, and the user's own rows.
* `by_recency` with `bump_event_types` and `by_name` are read per room through the indexes with a fixed row budget
  (ADR-0666), so no sort key passes over a whole table either.
