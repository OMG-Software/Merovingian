# Main reads a worker's store through readers opened before the sandbox

* Status: accepted
* Deciders: workstream S8 (C44 follow-up)
* Date: 2026-11-12

Technical Story: run-3 audit finding C44 follow-up; the FreeBSD package gate on PR #588 failed with
`Federation worker store: refused a room_list_page request (read_failed)` and then
`posix_spawn(...merovingian-fed-worker): Not permitted in capability mode`.

## Context and Problem Statement

Since [ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md) main reads each
federation worker's store from its database: the room list once per channel, then a room per permit
([ADR-0735](0735-a-worker-may-have-main-read-a-room-only-under-a-permit-main-issued-and-only-once.md)). Each read
opened its own connection, by the SQLite path or the PostgreSQL conninfo. On FreeBSD main enters Capsicum capability
mode right after it spawns the worker, and capability mode forbids opening a file by path or connecting a socket
([ADR-0377](0377-the-server-exits-when-its-federation-worker-cannot-start.md),
[ADR-0566](0566-the-clamd-socket-is-refused-at-startup-where-the-sandbox-forbids-connecting-to-it.md)). The worker's
first request therefore always failed, the worker stopped, and a restart cannot spawn in capability mode: no FreeBSD
server could run federation. How does main read for its workers once it is sandboxed?

## Decision Drivers

* The reads run after `cap_enter`, always: the first one comes from a worker spawned just before it.
* A read must hold no lock across anything but itself, never `runtime.mutex`, and end its transaction before page 0
  is sent (ADR-0735).
* A read must never block or fail main's own writes.
* The same code on every platform: a FreeBSD-only path would be tested only by the package gate.

## Considered Options

* A pool of read connections opened when `WorkerPool` is built (before `cap_enter`), one per shard, leased per read
* Lease a connection from the store's write pool (ADR-0154)
* Answer the worker from main's in-memory store under `runtime.mutex`
* Keep opening per read, and delay `cap_enter` until the worker's first fill has finished

## Decision Outcome

Chosen option: a pool of read connections opened before the sandbox. `database::SnapshotReaderPool` opens one reader per
shard (the snapshot service runs one thread per shard) when `WorkerPool` builds the snapshot service, which is before
`main.cpp` calls `cap_enter`. Every read leases one, and gives it back with its transaction ended. A SQLite reader is a
read-only connection that has made its first read at open, so a broken reader is logged at start, while it can still be
fixed. A PostgreSQL reader is set to the runtime role at open. A read opens a connection only to replace one it had to
close (a PostgreSQL connection the server dropped): that succeeds outside a sandbox and fails, as before, inside one. The
path- and conninfo-taking read functions remain and now open, then read through the same code.

### Rejected

* **The write pool.** After `cap_enter` it cannot open a second connection, so a write arriving while a read held the
  only one would fail outright instead of waiting.
* **Main's memory under `runtime.mutex`.** ADR-0733 and ADR-0735 rejected it: a worker could then make main hold the
  global lock for a whole room.
* **Delaying `cap_enter`.** A `room_sync` reload is needed for as long as the server runs, and each one reads.

### Consequences

* `tests/unit/test_snapshot_reader_pool.cpp` (`[c44][snapshot-readers]`) moves the database file away from its path,
  which makes every open by path fail as capability mode does, and shows the room list and room reads still succeed
  with no connection opened; it also reads from four threads at once through two readers. The FreeBSD package gate is
  the real-kernel proof.
* `Fed10HiddenDatabase` in `test_federation_worker_flow.cpp` used to fail a reload by moving the file away, which no
  longer fails a read. It renames the `rooms` table instead: a schema change reaches every connection.
* The pool holds `federation.worker.shards` read connections for the server's life.
