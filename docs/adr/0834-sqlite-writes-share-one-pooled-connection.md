# SQLite writes share one pooled connection, whatever database.pool_size says

* Status: accepted
* Date: 2026-11-18

Technical Story: the DB-7 scenario "concurrent writes to SQLite reuse at most database.pool_size connections" lost
three of its 64 writes in a full test run on a loaded VM: three writers logged `connection.rejected sqlite_code=5`
and `transaction.failed stage=open` together, 5.3 s after the store opened. Refines
[ADR-0154](0154-pool-database-write-connections.md), which assumed that SQLite's 5-second busy timeout absorbs
contention for its single writer lock.

## Context and Problem Statement

SQLite in rollback-journal mode (`journal_mode = DELETE`, pinned by every connection) has one writer at a time,
and a connection that wants a lock another connection holds does not queue for it. Its busy handler polls: it
sleeps 1, 2, 5 ... ms, then every 100 ms, and gives up after 5 s of sleeps (`sqliteDefaultBusyCallback`). A
committing connection holds PENDING or EXCLUSIVE for the whole commit, journal syncs, database write and database
sync included (`syncJournal` takes EXCLUSIVE before its first sync), and PENDING refuses every new SHARED lock. A
pooled connection that commits back to back therefore holds the lock nearly all the time. Its next lease takes the
lock again within microseconds, while another connection of the same process, polling every 100 ms by then,
rarely arrives in the gap.

With `database.pool_size` connections allowed, the pool opened a second, third and fourth SQLite connection while
the first was committing. Each needs a SHARED lock to read the schema when it pins its pragmas, and each of
them polled against the first for 5 s and was refused: a write the client is told failed, because another write of
the same process was busy. The same refusal follows for a write that waits behind one slow write for longer than
5 s.

Should SQLite writes keep up to `database.pool_size` connections?

## Considered Options

* **One SQLite write connection: the SQLite write pool's limit is always 1 (chosen).**
* Keep `database.pool_size` connections and lengthen the busy timeout, or retry a refused open.
* Keep `database.pool_size` connections and serialise their transactions with a mutex.
* Write-ahead logging (`journal_mode = WAL`).

## Decision Outcome

Chosen option: one connection, because SQLite runs one write transaction at a time anyway, so a second connection
adds no parallelism and only a second place to wait, and that place is SQLite's polling, unfair, time-limited
busy handler. With one connection, every write of this process waits in the pool, on a condition variable that
wakes the next writer when a lease ends and never times out, which is how ADR-0154 already waits for a PostgreSQL
connection.

* `SqliteWritePool` holds a `ConnectionPool` of limit 1, and `set_write_connection_limit` (that is,
  `database.pool_size`) changes only the PostgreSQL pool. `write_connections_opened` reports 1 for SQLite unless a
  connection could not be opened.
* SQLite's busy timeout still governs this process's reads against its writer, and every lock another process
  takes (`merovingian-db-migrate`, an operator's `sqlite3` shell). A read can still be refused after 5 s of
  back-to-back commits; that is not changed here.

### Positive Consequences

* No write is refused because another write of this process holds SQLite's lock, however long it holds it.
* A waiting writer is woken when the lease ends rather than at its next poll, and does no busy polling.

### Negative Consequences

* A write that never ends blocks every later write instead of failing them after 5 s each. A write is one
  transaction of statements built before the lease is taken, so nothing in it waits on anything but SQLite.

## Pros and Cons of the Options

### Lengthen the busy timeout, or retry a refused open

* Good, because it is a one-line change.
* Bad, because the wait stays unfair: a longer budget lowers the odds of a refusal under load but keeps it, and
  every waiter polls. It raises the tolerance instead of removing the contention.

### Several connections, serialised by a mutex

* Bad, because the connections would never be used at once; the extra handles are idle weight, and
  `database.pool_size` would claim a parallelism that does not exist.

### Write-ahead logging

* Good, because readers would no longer block a writer or be blocked by one.
* Bad, because the read-only connections refuse WAL on purpose
  ([ADR-0157](0157-never-open-a-sqlite-database-file-outside-sqlite.md): a read-only connection can still write
  the WAL index), and the pinned journal mode is a durability decision (#447). Changing them is a decision of its
  own.

## Links

* Refines [ADR-0154](0154-pool-database-write-connections.md)
