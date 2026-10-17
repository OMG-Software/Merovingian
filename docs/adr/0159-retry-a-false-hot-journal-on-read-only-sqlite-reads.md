# Retry a journal that only looks hot on read-only SQLite reads, for a bounded time

* Status: accepted
* Date: 2026-10-17

Technical Story: OpenBSD CI (runs 38952773715, 38968539347, both on PR #510) kept failing "main
key-admission overload survives real worker socket HTTP and unchanged transaction retry" after
ADR-0157: the federation worker's read-only room reload still failed (`room.reload_failed`), and
the proxy fell back to main for the retried transaction. The CI log named no SQLite error code.
The race below can be reproduced deterministically and fails exactly that kind of reload, so it
was taken for the cause. It was not: once the reload logged its stage, CI showed every OpenBSD
reload failing at open because a partially applied `unveil(2)` had hidden the database
(ADR-0162). The race is still real on any platform, and this retry still addresses it.

## Context and Problem Statement

Whenever a connection takes its SHARED lock, SQLite checks for a hot journal: first that the
journal file exists, then that no process holds the RESERVED lock. A writer in another process
that deletes its journal and then unlocks between those two checks makes its own successful
commit look like a crash: the journal existed, nobody holds RESERVED, and the journal then cannot
be opened. SQLite 3.53.1 documents this as a false positive (ticket #3883) "dealt with by the
playback routine". A read-write connection takes EXCLUSIVE, finds no journal and carries on. A
read-only connection cannot play anything back, so `pagerSharedLock` returns
`SQLITE_READONLY_ROLLBACK` at once, without calling the busy handler.

Every read-only connection in this server races main's commits: the federation worker's room
reloads and its startup load, media blob reads, and audit reads. The connection's first SHARED
lock is taken in `open_sqlite_connection` itself (`PRAGMA synchronous` needs the schema), and
again by every autocommit statement. On a slow, loaded VM the gap between the two checks is wide
enough to hit.

How should a read-only read survive a commit it happens to straddle?

## Considered Options

* Retry `SQLITE_READONLY_ROLLBACK` for a bounded time at each point that takes SHARED: the
  open-time pragmas, `prepare`, and a read statement's first step
* Run each read-only read in one read transaction, so SHARED is taken once, and retry only that
* Open the worker's connection read-write with `PRAGMA query_only`
* Use WAL mode
* Leave reads failing, and rely on the proxy's fallback to main

## Decision Outcome

Chosen option: retry at each point that takes SHARED, because it covers every read-only read path
without changing how long any of them holds a lock.

* `retry_false_hot_journal` reruns an operation while it fails and the connection's extended
  code is `SQLITE_READONLY_ROLLBACK`, pausing 10 ms, for up to 2 s. The race lasts microseconds,
  so the first retry normally succeeds.
* It wraps the open-time pragmas, `prepare`, and `first_step`, the first step of every read loop
  (`load_rows`, `load_rows_bound`, `load_table_names`, `load_schema_state`). The false positive
  can only appear when SHARED is taken, which is on a statement's first step, before any row
  is delivered, so rerunning that step is the same read.
* A journal that is really hot, left by a crashed writer, outlasts the budget. The read then
  fails as it did before, and leaves the journal for main's next read-write connection to roll
  back.
* A failed room snapshot now logs `room_snapshot.read_failed` with its stage and the extended
  SQLite code, so the next CI or production failure names its cause.

The rule for future code: **a read on a read-only SQLite connection steps through `first_step`
and prepares through `prepare`**, never through a bare `sqlite3_step` or `sqlite3_prepare_v2`.

### Positive Consequences

* The worker's room reload, its startup load, media blob reads and audit reads no longer fail
  because a commit happened to land between SQLite's two checks.
* Read-write connections are unaffected: they never return `SQLITE_READONLY_ROLLBACK`.

### Negative Consequences

* A read that meets a really hot journal waits up to 2 s more before it fails.
* Each statement is still its own snapshot. A room reload can still mix rows from before and
  after one of main's commits; that existed before this change and is not addressed here.

## Pros and Cons of the Options

### One read transaction per read-only read

* Good, because SHARED is taken once and the snapshot is consistent.
* Bad, because the worker's whole-store startup load would hold SHARED for its full length. Main's
  writers wait at most their 5 s busy timeout for EXCLUSIVE, so on a large store, writes would
  start failing whenever the worker restarted.

### Read-write connection with `query_only`

* Good, because SQLite would settle the false positive itself, under EXCLUSIVE.
* Bad, because the worker would hold a writable descriptor and roll back journals, which ISO-4
  and the worker's read-only Landlock rules exist to prevent.

### WAL mode

* Good, because readers never check for a hot rollback journal.
* Bad, because read-only WAL readers write the shared-memory index, which is why ISO-4 refuses
  WAL for the worker.

### Rely on the fallback to main

* Good, because no change.
* Bad, because main then serves the room from its own state until the next successful reload,
  and the fallback is what let a retried transaction be processed twice (see ADR-0160).

## Links

* Refines [ADR-0157](0157-never-open-a-sqlite-database-file-outside-sqlite.md): that fixed a lost
  lock that made journals look hot for as long as a transaction ran; this fixes the narrow window
  SQLite itself leaves.
* [ADR-0160](0160-main-records-every-completed-federation-transaction.md) makes a reload failure
  harmless to transaction dedupe.
