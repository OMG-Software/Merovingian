# The federation worker opens no database; main sends it what it reads

* Status: accepted
* Deciders: owner (option and both backends, 2026-11-12), workstream S8
* Date: 2026-11-12

Technical Story: run-3 audit finding C44,
`F-resource-exhaustion.sqlite-worker.read-lock-held-by-compromised-worker-fails-every-main-write`.

## Context and Problem Statement

On SQLite the federation worker opened main's database file read-only. Read-only stops writes, not locks: a worker
holding SQLite's SHARED lock (an open `BEGIN DEFERRED`, or a bare `fcntl(F_RDLCK)` on the lock bytes) makes every COMMIT
in main wait its 5 s busy timeout and fail, for as long as it likes, while its IPC channel stays healthy. On PostgreSQL
the worker had a SELECT-only login (ADR-0062 part 2). A reader does not block a writer there, but that login could still
open connections up to `max_connections` (the role had no `CONNECTION LIMIT`), hold main's migration advisory lock,
pin the cluster's xmin horizon with a transaction left open (`idle_in_transaction_session_timeout` is user-settable),
and queue an `ALTER TABLE` behind its `ACCESS SHARE` locks. How does the worker get the rows it reads without any handle
on main's database?

What the worker read: at start-up the whole store (SQLite: every table, the load profile was honoured only by the
PostgreSQL loader; PostgreSQL: the 13 tables of `federation_worker_table_allowlist`); on each `room_sync` one room's
rows in one read transaction (`load_room_snapshot`, ADR-0161); and on a key-cache miss one server's public key rows
(`refresh_remote_signing_keys`). Every other worker read is of its own memory, and every write already relays to main.

## Decision Drivers

* No lock, connection, transaction or descriptor the worker holds may reach main's database, on either backend.
* One path for both backends, reusing the code that reads a room in one snapshot.
* The worker must not hold more data than before.

## Considered Options

* (a) The worker gets its rows from main over the existing IPC channel
* (b) Main writes a read-only snapshot file per shard and the worker opens that
* (c) Keep the database, and have main detect and kill a worker that holds a lock
* For PostgreSQL only: keep the SELECT-only login and add `CONNECTION LIMIT`

## Decision Outcome

Chosen option: (a), on both backends (owner, 2026-11-12). The worker's configuration copy is switched to
`database.backend=memory` before Landlock and the runtime start (`federation_worker::clear_database_location`, in
`main.cpp` before the Landlock rules are built and again in `WorkerEventLoop::run()` before the runtime starts, as the
master-key path is cleared); it is given no database path, URI, descriptor or Landlock grant.

* **Start-up.** Before it starts its runtime the worker asks main for the room list (`room_list`, paged) and then each
  room in turn (`room_snapshot`, paged), and builds its store from them (`RuntimeStartOptions::fill_store`, before
  hydration), so its runtime hydrates exactly as before (rosters included) from memory. The scope is every room, as
  before; only the shard's own rooms get `room_sync`. Rooms are fetched one at a time, not pipelined: main holds the
  pages of one snapshot per channel. A room list main refuses or does not answer stops the worker, and the supervisor
  restarts it; a room main cannot send is logged and left out, and its next `room_sync` fills it, because one bad
  room must not keep every other room's federation down. A server on the `memory` backend lists no rooms, so its
  workers start empty, as they did when each opened a memory store of its own. The channel is started before the
  runtime, so the fill can have its replies; frames main sends meanwhile wait behind a gate in front of the request
  handler, which opens once the runtime exists and closes before the channel stops.
* **Reloads.** `room_sync` stays a notification. The reload, still coalesced per room on the reload thread (ADR-0623),
  asks main for the room and applies it with `apply_room_snapshot` under the `StoreReadGuard` (ADR-0360). Whole-room
  snapshots per coalesced round; no deltas.
* **Keys.** On a key-cache miss the worker asks main for one server's public key rows (`server_keys`, through
  `PersistentStore::remote_signing_key_source`); main answers from its in-memory table, public columns only, never a
  row that holds a secret (so never this server's own keys) and never the network. The worker starts with no keys and
  learns each server's on its first miss. The miss is taken in both of the worker's lookups: `cached_pdu_key_lookup`
  (PDU and X-Matrix verification, which never runs discovery) and the resolver (`KeyMirrorRefresh::on_miss`). Only the
  resolver would have been enough for a key main fetched after the worker started, as before; but every key now starts
  missing, and a key main already verified must not need discovery of its server before the worker can use it, which
  the resolver's cache hit requires. It cannot resolve this server's own keys: the resolver takes those only
  from rows that hold the secret (FED-1, ADR-0083), which a PostgreSQL worker never had and a SQLite worker no longer
  has.
* **Main's side.** Main reads a room with `database::load_room_snapshot` from its own database on a snapshot thread,
  never under `runtime.mutex`, in one read transaction that is closed before the first page is sent: a worker that reads
  slowly cannot hold a lock in main's database through main.
* **Snapshot contents.** A room's snapshot now carries its forward extremities as well, read in the same transaction,
  since start-up no longer loads that table whole.
* **What the worker no longer holds.** On SQLite: users, token hashes, the sealed signing secret, account data, keys,
  to-device rows and policy rules. On both: any database credential. The worker's policy view was already advisory
  (ADR-0358, ADR-0359); it now holds no policy rules on either backend.
* **Retirement.** `federation.worker.database_uri_file`, `federation.worker.allow_shared_database_credentials`,
  `--db-uri-fd`, `database.worker_conninfo_override` and the PostgreSQL worker role script go; the two keys are refused
  at parse with an error naming the key ([ADR-0736](0736-the-retired-worker-database-keys-are-refused-at-parse.md)).
* **Writes on the channel.** A failed write ends the channel ([ADR-0734](0734-a-failed-ipc-write-ends-the-channel.md)):
  large answers make a stalled write plausible, and a half-written frame breaks the stream for good.

### Positive Consequences

* A compromised worker holds no descriptor, lock, login or Landlock grant on main's database, so C44 and the
  PostgreSQL exposures above are gone as a class.
* The SQLite worker holds less than before: the allowlisted rows only.

### Negative Consequences

* Start-up is one round trip and one indexed read per room instead of one table scan; a server with many rooms starts
  its worker more slowly, and federation requests main forwards meanwhile wait, as they did during hydration.
* Each reload costs main the read the worker used to make, plus serialisation and encryption. It runs on a bounded
  snapshot pool with no lock held, one held snapshot per channel.
* A crash-looping worker makes main read every room once per restart, bounded by the supervisor's 1-30 s back-off.

## Pros and Cons of the Options

### (b) A snapshot file per shard

* Bad, because keeping it fresh means main writes into a file the worker can lock (the same failure, moved), or writes
  whole immutable generations, which cannot keep up with a busy server and still needs IPC for freshness.
* Bad, because every write to an allowlisted table is written once more per shard, and PostgreSQL would need an
  exporter to SQLite that does not exist.

### (c) Detect and kill a lock holder

* Bad, because main sees only `SQLITE_BUSY`, which honest contention also causes, and the worker can take the lock
  again after each restart. It treats the symptom on one backend.

### PostgreSQL: keep the login with CONNECTION LIMIT

* Bad, because it closes connection exhaustion only, not the advisory lock, the xmin horizon or DDL blocking, and keeps
  a second data path to maintain and test.

## Links

* Supersedes part 2 of [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
  (the worker's PostgreSQL login) and its SQLite Landlock grant (part 3)
* Followed by [ADR-0734](0734-a-failed-ipc-write-ends-the-channel.md),
  [ADR-0735](0735-a-worker-may-have-main-read-a-room-only-under-a-permit-main-issued-and-only-once.md) and
  [ADR-0736](0736-the-retired-worker-database-keys-are-refused-at-parse.md)
* Related [ADR-0161](0161-room-reloads-read-one-snapshot-the-whole-store-load-does-not.md),
  [ADR-0360](0360-the-worker-guards-its-store-with-a-reader-writer-lock-taken-only-for-the-swap.md),
  [ADR-0623](0623-a-workers-room-reloads-are-coalesced-per-room-on-one-thread.md)
