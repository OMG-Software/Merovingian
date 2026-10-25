# A scenario that asserts on every store write runs on a PostgreSQL database of its own

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-25

Technical Story: "DB-6 PostgreSQL inbound admission rejects escaped NUL state keys before
any write" failed in `postgres-integration` on PR #534 with `statements written while
rejecting: upsert_federation_transaction`, while `main` with the same C++ passed

## Context and Problem Statement

The DB-6 scenario proves a rejected PDU writes nothing: it turns on statement capture for
the whole store around the rejection and requires `captured_statements` to be empty.
The live PostgreSQL scenarios all run on one shared database. When the scenario's runtime
starts, the dispatch worker replays every `federation_transactions` row an earlier
scenario left there (`DispatchWorker::replay_pending`), tries to deliver each to a server
that does not exist, and re-persists it with a higher retry count from its own thread,
whenever that attempt fails. A retry that lands inside the capture window is charged to
the rejection. Whether it does depends on which scenarios ran first and how long each
failed delivery takes, so the scenario failed at random.

How should a scenario that asserts on every write keep the strength of that assertion
without depending on what other scenarios left behind?

## Decision Drivers

* The assertion must still fail if the code under test writes anything, on any thread,
  including queuing an outbound transaction.
* The scenario must not depend on test order or timing.
* No test-only hook added to production code for this.

## Considered Options

* Ignore `upsert_federation_transaction` in the captured statements
* Stop the dispatch worker before the capture window
* Capture only the statements the test's own thread commits
* Run the scenario on a PostgreSQL database of its own

## Decision Outcome

Chosen option: "Run the scenario on a PostgreSQL database of its own", because it removes
the cause, the foreign rows, and keeps the store-wide assertion exactly as strict. The
scenario creates `merovingian::tests::ScratchPostgresqlDatabase`
(`tests/integration/scratch_postgresql_database.hpp`, moved there from
`test_database_upgrade_flow.cpp`, its first user) before its runtime, so the database
outlives every connection and is dropped when the scenario ends. Before each capture
window it also requires that the dispatch worker, if it was started, holds nothing
pending, so background outbound work reintroduced later fails the scenario at once
instead of at random.

Rule for future work: a live PostgreSQL scenario that asserts on every write the store
commits, or that needs an empty schema, runs on its own database. Do not narrow the
assertion to make a shared database pass (see `docs/testing-standards.md`).

### Positive Consequences

* The scenario is deterministic and its assertion unchanged.
* Rows other scenarios leave in `deferred_pdus`, which a background retry job also replays,
  cannot leak into it either.
* One scratch-database fixture serves both files that need one.

### Negative Consequences

* The scenario needs a role allowed to `CREATE DATABASE`, as the upgrade scenarios
  already do; CI's test role is the container's bootstrap superuser.
* Creating and dropping a database adds a little time to the scenario.

## Pros and Cons of the Options

### Ignore `upsert_federation_transaction` in the captured statements

* Good, because it is one line.
* Bad, because a rejection that wrongly queued an outbound transaction writes exactly that
  statement, so the test could no longer see the bug it most needs to catch.

### Stop the dispatch worker before the capture window

* Good, because the worker then writes nothing.
* Bad, because `DispatchWorker::enqueue` refuses work during shutdown without persisting
  it, which again hides a rejection that queues outbound work; and it leaves the other
  replayed queues alone.

### Capture only the statements the test's own thread commits

* Good, because background threads drop out of the capture.
* Bad, because it needs a test-only field in `PersistentStore`, and it misses any write the
  rejection triggers on another thread.

## Links

* [docs/testing-standards.md](../testing-standards.md) — "Live PostgreSQL scenarios that need a quiet store"
* Related: [ADR-0216](0216-upgrade-path-is-tested-from-a-forward-only-seam-and-a-real-previous-release-fixture.md),
  whose upgrade scenarios introduced the scratch database
