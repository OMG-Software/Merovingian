# An ingest that writes a current-state row commits under the runtime lock

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit C41,
`F-data-lifecycle.pdu-ingest-commit-window.prepared-state-row-applied-over-concurrent-local-write`.

## Context and Problem Statement

`ingest_pdu_event` prepares a PDU's rows under `runtime.mutex`, releases `runtime.mutex` (keeping only the room stripe)
for the backend commit, and then applies the prepared rows to memory. A local client's state write takes
`runtime.mutex` but no stripe, so it can prepare the same `current_state` row from memory inside that window, commit
after the ingest, and apply first. Memory then ends with the ingest's row and the database with the local one, and a
restart serves the database's. The same holds for the membership projection rows committed with a member event.

What keeps memory equal to what the database holds for every row a commit touches?

## Decision Drivers

* Invariant: what memory holds after a commit equals what the commit wrote, for every row it touched.
* Independent rooms keep committing messages concurrently: most PDUs write no shared row.
* Every writer of a `current_state` or membership row must be covered, including ones added later.

## Considered Options

* Keep `runtime.mutex` across the commit when the prepared update writes a `current_state` or membership row.
* Take the room stripe on every local path that writes current state.
* Re-check at apply time that the in-memory row still names what prepare saw, and re-prepare or refuse if not.

## Decision Outcome

Chosen option: "Keep `runtime.mutex` across the commit when the prepared update writes a `current_state` or membership
row", because every writer of those rows already holds `runtime.mutex`, so no writer can prepare one from memory
between this prepare and this apply, whatever path it comes from.

* `ingest_pdu_event` releases `runtime.mutex` for its commit only when `PreparedStateUpdate::state` and `membership` are
  both empty (a message, or a rejected or soft-failed event): those commits write the event's own rows, which no other
  writer touches. An update with either keeps the lock, as a local send's commit already does.
* The backfill commit stores no state row and keeps releasing the lock.
* A new path that commits a prepared update with `runtime.mutex` released must write no row another writer can prepare
  from memory, or keep the lock.

### Positive Consequences

* Memory and the database agree on every `current_state` and membership row after any interleaving of federated and
  local writes, and a restart serves what the running server served.
* The fix is one decision at one site; local paths are unchanged.

### Negative Consequences

* A federated state event's commit now holds `runtime.mutex`, as every local state event's commit already did: other
  rooms wait for one backend transaction per accepted state PDU. A message PDU still commits without it. The work is one
  transaction of bounded size per PDU, not work that grows with remote input.

## Pros and Cons of the Options

### Take the room stripe on every local write path

* Good, because it would keep the federated commit concurrent with other rooms.
* Bad, because current state is written from many local paths (state sends, membership changes, room creation, profile
  fan-out, upgrades), and each must take the stripe in stripe-then-runtime order; one missed path, now or later, reopens
  the race.

### Re-check at apply

* Good, because it keeps the commit outside the lock.
* Bad, because apply cannot tell which of two committed writes the database kept: with PostgreSQL row locks and SQLite's
  write lock the order of commits is not the order of applies, so a re-check only detects the race, it cannot repair it
  without reading the row back from the backend under the lock.

## Links

* Relates to [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md)
