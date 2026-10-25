# Pre-1.0 migrations collapse into one v1 schema, frozen at 1.0.0, and an unknown ledger is refused

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-25

Technical Story: release preparation (0.12.47); the 1.0.0 collapse ADR-0216 anticipated

## Context and Problem Statement

By 0.12.46 the schema was built by 26 migration steps: a v1 bootstrap and 25 steps that
created tables, ALTERed columns on, added indexes, and backfilled or seeded rows for
databases that already existed. To keep the chain applicable, `schema.cpp` held each
ALTERed table in its v1-era shape and patched the current shape back in by hand (`rooms`),
and every later table sat on a `vN_table_names` list. No deployment runs this software,
and the owner does not support upgrades from before 1.0 (ADR-0216), so the chain carries
cost and no benefit. Upgrades from 1.0.0 onward must work.

How should the schema be expressed for release, so that it is simple now and stays safe
to migrate after 1.0.0?

## Decision Drivers

* A fresh database must end in exactly the shape the 26 steps produced: every column, in
  the same physical order (some writes are positional `INSERT ... VALUES`), and every index.
* After 1.0.0, v1 must never change underneath a deployed database.
* A database the old chain wrote must never be misread as the new v1, now or after a
  future release reaches version 26 again.
* The fewest moving parts, but no loss of the safety the migration runner already has
  (per-step atomicity, PostgreSQL's migration role and lease).

## Considered Options

* Keep the 26-step chain
* One v1 step generated from the table registry, frozen by a checked-in file and a test
* One v1 step written as literal SQL text in C++
* Drop the migration framework and create tables from the registry on every open

## Decision Outcome

Chosen option: "One v1 step generated from the table registry, frozen by a checked-in
file and a test". `core_tables` in `schema.cpp` now holds every table in its final shape,
each formerly ALTERed column placed after the table's other columns and before its
`PRIMARY KEY (...)` clause (exactly where `ADD COLUMN` put it), and `core_indexes` holds the
four secondary indexes. `initial_schema_migration()` creates both; the SQLite and
PostgreSQL bootstraps create the same set. `current_schema_version()` is 1, and both
catalogs hold one step. `migrations/001_initial_schema.sql` is the only migration file,
and a unit test requires it to equal the build's v1 step statement for statement.

Every upgrade row of a database's `schema_migrations` ledger must name the step this build
has at that version (`schema_ledger_is_known`). Both stores check it as soon as the ledger
is read, before migrating or hydrating, and refuse otherwise; the forward-only seam
(`migrate_*_schema_to`) checks it too. A version number alone could not tell the builds
apart: every pre-collapse build also wrote a v1 row named `initial_schema`, and its rows 2
to 26 name steps that no longer exist. That is what refuses a pre-1.0 database today, and
still refuses it after some future release has a v26 of its own.

Rules this sets for future work:

* **Until 1.0.0 is cut**, a schema change edits `core_tables`/`core_indexes` and
  `001_initial_schema.sql` together. A database created by an earlier 0.12.x build may then
  no longer match; that is accepted before 1.0.
* **From 1.0.0, v1 is frozen.** A schema change is a new numbered migration (v2, ...) added
  to both catalogs and as `migrations/002_*.sql`. The first such migration must split
  `initial_schema_definitions()` (what v1 created, unchanged) from
  `current_schema_definitions()` (what v1 plus v2 leave), because today both return the
  same registry; the file-equality test fails if v1 changes by accident.
* Never rename a step, and never reuse a version number: the ledger check identifies a
  step by both.

The collapse also moves all of a fresh PostgreSQL database's DDL into the bootstrap, which
ran as the login role. Steps 2 to 26 used to run under `database.migration_role`, so the
migration role would have owned nothing on a fresh install, and the first post-1.0
migration would fail its `ALTER` there. The bootstrap now assumes the migration role too,
and fails closed when it cannot, as `packaging/postgresql/provision-roles.sql` already
said it did.

### Positive Consequences

* One place describes each table; the v1-era shapes, the `vN_table_names` lists, the
  `rooms` special case and 50 step functions are gone.
* A pre-1.0 database fails at open with a reason naming the unknown migration, instead of
  being half-read or failing later at an unrelated query.
* The migration role owns every table of a fresh PostgreSQL install, so the first post-1.0
  migration runs as their owner.

### Negative Consequences

* Every pre-1.0 database must be recreated; there is no upgrade from 0.12.46 or earlier.
* The 0.11.13 fixture and its scenarios are removed, as ADR-0216 planned; until the last
  1.0.x release writes the next fixture there is no real-release upgrade evidence, and the
  "any older version" scenario covers nothing until v2 exists.
* The freeze of v1 rests on a test comparing it with a checked-in file, not on the type
  system.

## Pros and Cons of the Options

### Keep the 26-step chain

* Good, because nothing changes.
* Bad, because every table is described twice (v1-era and current) for upgrades nobody
  needs, and the trap ADR-0216 recorded (a column listed in both the v1 shape and an ALTER
  aborts the chain) stays live.

### One v1 step written as literal SQL text in C++

* Good, because v1 is visibly frozen in the source.
* Bad, because the registry still has to describe the same tables for the DDL allowlist
  and the table inventory, so the schema would again be stated twice, now in two forms.

### Drop the migration framework and create tables from the registry on every open

* Good, because it is the least code.
* Bad, because after 1.0.0 the first schema change would need the framework back, and the
  PostgreSQL migration lease, role separation and per-step atomicity it carries would have
  to be rebuilt under pressure.

## Links

* Refines [ADR-0216](0216-upgrade-path-is-tested-from-a-forward-only-seam-and-a-real-previous-release-fixture.md):
  the collapse it planned for 1.0.0 happened in 0.12.47, before the release, and the
  fixture it named is removed
* [docs/database-persistence.md](../database-persistence.md) — schema and migration policy
* [migrations/AGENTS.md](../../migrations/AGENTS.md) — migration file rules
