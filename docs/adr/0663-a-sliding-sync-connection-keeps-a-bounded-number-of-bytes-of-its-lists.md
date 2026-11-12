# A sliding sync connection keeps a bounded number of bytes of its lists

* Status: Accepted
* Date: 2026-11-12

Technical Story: security audit run 3, finding C06

## Context and Problem Statement

A sliding sync connection keeps the lists of its last request (`list_configs`, and a second copy in
`pending_response` until the next request acknowledges it) and its `conn_id` (inside the map key) for an hour. Only the
number of connections was capped, not their size: `room_types`, `not_room_types`, ranges, `conn_id` and strings in
`required_state` were free up to the 1 MiB body, and a retained string weighs about ten times its three bytes on the wire.
One account with 200 devices of 16 connections could hold tens of GiB. How is the retained size bounded?

## Decision Drivers

* The bound must not depend on how many connections or devices exist.
* Element X and other real clients send a few short strings; they must never notice.
* The check runs per request under the runtime lock.

## Considered Options

* Count caps only (`room_types` 16, ranges 16, `conn_id` and list names 255 bytes).
* A byte budget only.
* Count caps plus a byte budget per connection, plus a byte budget per device.
* Evict the least recently used connections when a device is over budget.

## Decision Outcome

Chosen option: "count caps plus a byte budget per connection and per device", because the count caps give the
specific, explainable errors for the fields the audit named, and the byte budget bounds every remaining free-length
string (`required_state` types, `sort`, `bump_event_types`, filter strings) that a count cap alone would leave.

* Caps in `SlidingSyncLimits`: 16 `room_types` and 16 `not_room_types` per list, 16 ranges per list, 255 bytes for a
  `conn_id` and for a list name. Over a cap the request is 400 `M_INVALID_PARAM`, before any connection state exists.
* `sliding_sync_retained_bytes` measures a request (or stored `list_configs`) at its in-memory size: each string is
  `sizeof(std::string)` plus its length, each range `sizeof(SlidingSyncRange)`, each list its struct and a map node.
  A request keeping more than 65,536 bytes is refused (`retained_bytes_per_connection`).
* Across one device the request's bytes plus the committed and pending lists of the device's other connections may not
  exceed 262,144 bytes (`retained_bytes_per_device`). The handler walks only that device's key range, at most
  `sliding_sync_connections_per_device` entries, and refuses with 400 before creating the entry. The connection being
  replaced is not counted against itself: its old lists are dropped when the new request is acknowledged.
  One account at 200 devices therefore keeps at most about 50 MiB (pending lists are inside the count).
* These are fixed policy like the other list-shape caps, not configuration.

### Rejected: evict least recently used connections over the device budget

It looks gentler, but a client that is over budget would have its working connection evicted by its own other
connection and the two would fight, each eviction costing a full initial sync. A 400 tells the client which request is
too large and costs the others nothing.

### Rejected: count caps only

A `required_state` type, a sort key or a filter string can be as long as the body; counting entries leaves that open.

### The idle-connection sweep reads an index, not the table

`prune_sliding_sync_connections` ran on every request and walked every connection of every user to find the idle ones,
under `runtime.mutex`. `HomeserverRuntime::sliding_sync_connections` is now a `SlidingSyncConnectionTable`: the map and
a set of `(last_used, key)` ordered oldest first. Every change goes through `touch` (create or refresh, which moves the
index entry), `erase` (the unknown-`pos` drop and the per-device least-recently-used eviction) or `erase_idle` (pops from
the front until the first connection that is not idle), so the two cannot differ; `states()` is read-only. The sweep
costs the connections it removes plus one entry looked at, however many connections other users hold
(`idle_entries_visited()` is what the test reads). No other path erases connections: logout and device deletion leave a
connection to the idle sweep, as before.

Rejected: a sweep that only runs every N requests or every N seconds. It bounds the frequency but not the cost of a
sweep, and a long-lived server would still pay O(connections) in one request.

## Consequences

* A client asking for more than 16 room types or 16 ranges in a list now gets 400; none known does.
* The table keeps each connection's key twice (map and index); the number of connections is bounded per device and by the
  device and account limits, so this is a constant factor.
