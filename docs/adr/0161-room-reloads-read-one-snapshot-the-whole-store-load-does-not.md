# A room reload reads one snapshot; the worker's whole-store load does not

* Status: accepted
* Date: 2026-10-17

Technical Story: found while fixing the OpenBSD CI failures (ADR-0159, ADR-0160). The federation
worker serves room-scoped federation reads (`/state`, `/state_ids`, `make_join`, `/event`) from
the snapshot `reload_room` builds after each of main's commits.

## Context and Problem Statement

`load_room_snapshot_impl` read a room's rows as eight statements: rooms, membership, invites,
events, current_state, event_edges, event_auth, event_signatures. Without an explicit
transaction each statement is its own read: SQLite autocommit takes and drops SHARED per
statement, and PostgreSQL's default READ COMMITTED gives each statement a fresh snapshot. A
commit by main between two of them gave the worker a room that never existed. For example, the
current state could name an event the snapshot did not hold, because the event was committed
after the events read and its state row before the current_state read. The scenarios "A room
snapshot reads one committed state of the room even while main commits between its reads"
(SQLite) and its PostgreSQL twin reproduce exactly that.

Which reads must see one committed state, and how?

## Considered Options

* Read each room snapshot in one transaction: `BEGIN DEFERRED` on SQLite, `BEGIN ISOLATION LEVEL
  REPEATABLE READ READ ONLY` on PostgreSQL; leave the whole-store load as it is
* Read the whole-store load in one transaction too
* Detect a torn snapshot after the fact (e.g. state naming a missing event) and reload again

## Decision Outcome

Chosen option: a transaction per room snapshot only, because a room snapshot is small and its
rows are read together, while the whole-store load is neither.

* SQLite: `SqliteReadTransaction` begins a deferred transaction before the first read and ends it
  after the last. The first read takes SHARED, and SQLite holds it until the end, so a writer's
  commit waits. ADR-0159's retry still applies, since that first read is where SQLite checks for
  a hot journal.
* PostgreSQL: one REPEATABLE READ, READ ONLY transaction, so every statement uses the snapshot
  taken at its first. Writers are not blocked.

The rule for future code: **a read that combines rows from more than one table into one picture
of a room runs in one read transaction**. **The worker's whole-store load stays per-statement.**

### Positive Consequences

* The worker never serves a room in a state main never committed.
* PostgreSQL readers and writers do not wait for each other.

### Negative Consequences

* On SQLite, main's commits wait for an in-flight room reload, which reads one room's rows. Main's
  writers wait up to their 5 s busy timeout, far longer than a room reload takes.
* The worker's startup load can still mix rows from before and after a commit. It is replaced
  room by room as `room_sync` reloads arrive, and a worker restart reloads it whole.

## Pros and Cons of the Options

### The whole-store load in one transaction too

* Good, because the worker's startup state would be consistent as well.
* Bad, because on SQLite it would hold SHARED for the whole load, and on a large store main's
  writes would fail their 5 s busy timeout whenever the worker restarted (ADR-0159).

### Detect and reload

* Good, because no lock is held.
* Bad, because catching every tear needs a cross-check for each pair of tables (memberships
  against current state, events against edges, and so on), and a busy room could reload without
  end.

## Links

* Refines [ADR-0159](0159-retry-a-false-hot-journal-on-read-only-sqlite-reads.md), which recorded
  the torn room snapshot as not addressed and rejected the whole-store transaction.
