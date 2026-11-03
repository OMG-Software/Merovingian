# The worker guards its store with a reader-writer lock that a reload takes only for the in-memory swap

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, F-27 (`fed.worker-store-providers-unlocked-against-reload-room`)

## Context and Problem Statement

The federation worker answers room-scoped reads (ACL, room version, state, state_ids, event_auth,
get_missing_events, backfill, timestamp_to_event, hierarchy) from its own `PersistentStore` on its request threads,
while `room_sync` rewrites one room of the same store on another. The tables have no lock of their own, `reload_room`
erases a room's rows and puts them back table by table, and a view into a table (`state_groups`, `state_group_state`,
`event_state_groups`, the `store.state` position indexes of ADR-0344) is valid only until the next write. The old
comment and rule 6 of `src/federation_worker/AGENTS.md` said a relay transaction holds `runtime.mutex` across its round
trips, which would have excluded the reload. It does not: `handle_federation_http_request` drops the mutex before
dispatch. So reads raced writes (undefined behaviour), and a reader between the erase and the re-insert saw a room with
no ACL, and `room_server_acl_allows` answered true.

## Decision Drivers

* The same provider lambdas run in main, where the store is guarded by `runtime.mutex`; whole-table scans must not move
  under that mutex (the project's recurring stall class).
* A reload must not read the database while readers wait.
* A lock held across IPC would let one pending writer block every later reader.

## Considered Options

* Take `runtime.mutex` inside every store-reading provider
* Publish an immutable per-room snapshot
* A reader-writer lock in the worker's wiring, with the reload split into a database read and an in-memory swap

## Decision Outcome

Chosen option: "reader-writer lock in the worker's wiring".

* `database::reload_room` is split: `load_room_snapshot` reads the database and does not touch the store;
  `apply_room_snapshot` swaps the room's rows. `reload_room` is both, for callers that need no lock.
* `federation_worker::StoreReadGuard` owns one `std::shared_mutex`. `wrap_store_readers` wraps the worker's copy of each
  store-reading provider so it holds the shared lock for its own call and returns values it owns; `reload_room` loads with
  no lock and takes the exclusive lock only for the swap. Reloads are serialised with each other by a separate mutex so
  the last one to run holds the freshest read.
* The wrapping comes before the overrides that relay to main, so no relay holds the lock. Main's lambdas are untouched.
* Rule for future worker code: a read of a table `reload_room` rewrites goes through a wrapped provider, or holds the
  shared lock, and copies what it keeps before releasing it. Never wait on another process under the lock.

### Positive Consequences

* A reader sees a room before or after a reload, never during it: an ACL read is never "no ACL" because of a reload.
* The database read runs with no lock held, so readers wait for a memory swap, not for I/O.

### Negative Consequences

* The swap still walks whole tables (the existing `erase_if` passes); readers wait for them. Shrinking them is separate work.
* The swap does not take `runtime.mutex`. Worker code that reads these tables under `runtime.mutex` alone, outside a
  wrapped provider, is not covered; there is none today.

## Pros and Cons of the Options

### `runtime.mutex` in every provider

* Bad, because it puts whole-table reads under the global mutex in main, and serialises the worker's readers with each other.

### Immutable per-room snapshots

* Good, because readers never wait.
* Bad, because every table reader changes shape, and the tables are shared with main.

## Links

* Refines [ADR-0161](0161-room-reloads-read-one-snapshot-the-whole-store-load-does-not.md) (the database read of a reload is one
  transaction; this is its publication to memory) and [ADR-0305](0305-a-worker-room-reload-carries-the-rooms-state-groups.md);
  relates to [ADR-0359](0359-main-judges-relayed-events-against-its-own-server-acl.md)
