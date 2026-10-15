# Pool database write connections up to database.pool_size

* Status: accepted
* Date: 2026-10-15

Technical Story: 29 September 2026 security audit, finding DB-7 (every persisted write opens a fresh
database connection while the global mutex is held). Builds on the per-room commit stripes of
[ADR-0009](0009-serialize-inbound-pdu-ingestion-on-per-room-stripes.md), whose commits run with the
runtime lock released.

## Context and Problem Statement

Each committed write opened its own connection: for SQLite a descriptor-relative, no-follow open with
its pragmas (DB-10); for PostgreSQL a connect, possibly a TLS handshake, and `SET ROLE`. Most writes run
with `runtime.mutex` held, so that cost was paid by every request waiting for the lock, and it amplified
the denial-of-service findings. `database.pool_size` was configured but unused.

## Considered Options

* **A blocking pool per backend, at most `database.pool_size` connections in use, reused between writes
  (chosen).**
* One long-lived writer connection. Rejected: PostgreSQL commits from independent room stripes run with
  the runtime lock released and would serialise again.
* Keep a connection per write. Rejected: the cost the audit names.

## Decision Outcome

Chosen option: `database::ConnectionPool`, one per store, created when the store is opened and shared by
copies of it; `bootstrap_local_database` applies `database.pool_size` through
`set_write_connection_limit`.

* A lease is held for exactly one transaction and nothing that holds one asks for another, so a writer
  waiting for a free connection cannot deadlock.
* PostgreSQL connections assume the runtime role once, when opened. A pooled connection is reused only
  if it is idle (`PQTRANS_IDLE`) and its socket has nothing to read: this server never `LISTEN`s, so a
  readable idle socket means the server sent a termination notice and closed it (restart, idle reaper,
  `pg_terminate_backend`), and the connection is replaced. One that a failed transaction left unusable
  is closed instead of returned.
* SQLite connections keep their pragmas and `foreign_keys=ON` from when they were opened; a failed
  transaction rolls back and the handle stays usable. The 5-second busy timeout absorbs contention for
  SQLite's single writer lock.
* Reads, migrations and the worker's read-only store keep opening their own connections.
* `database.pool_size` now requires a restart: the pool is built when the store opens.

### Negative Consequences

* A connection that dies in the instant between the readiness check and use still fails that write, as
  a fresh connection dying mid-transaction always did.
* A replaced SQLite file is not reopened by pooled handles until restart (they keep the file they
  opened, which is also what the DB-10 no-follow checks protected).
