# The schema is built from per-version tables, and each migration step from what its version adds

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 3 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), migration 002, the first after the
frozen v1 schema

## Context and Problem Statement

Until 1.1.0 the whole schema was one step, so `Schema.cpp` held one list of tables and indexes and the v1 step, the
bootstraps and the compatibility check all read it. Migration 002 adds two tables. The bootstraps must keep building
exactly what 1.0.x built, so that a fresh database and a 1.0.x database reach the current version by the same path,
while the compatibility check and the DDL allowlist must know every current table. How are "what v1 has" and "what
the current schema has" kept apart without copying table definitions?

## Decision Drivers

* v1 must never change (ADR-0224); `migrations/001_initial_schema.sql` is compared to the build's v1 step.
* A fresh database must end with exactly the schema a migrated one does.
* A table's DDL must be written once.

## Considered Options

* Per-version arrays in `Schema.cpp` (`core_tables`/`core_indexes` for v1, `oauth_tables`/`oauth_indexes` for v2),
  `schema_definitions_added_by(version)` and `schema_indexes_added_by(version)`, with the initial lists being version
  1 and the current lists the concatenation of versions 1 to `current_schema_version()`.
* Have the bootstraps build the current schema and record every ledger row at once.
* Write migration 002's DDL by hand in `Migration.cpp`.

## Decision Outcome

Chosen option: per-version arrays. A migration step is generated from what its version adds
(`schema_step_creating`: CREATE TABLE for each table, then CREATE INDEX for each index; `schema_step_dropping`: DROP
TABLE in reverse order, to the version before). The bootstraps build only version 1 and write ledger row 1, and
`apply_pending_migrations` then runs 002 on a fresh and a migrated database alike. Every table of every version is
allowlisted for DDL (`schema_table_is_core`, `index_is_registered`). `merovingian-db-migrate --migrations` now plans
only the files between its two versions, so `--plan 1 2` takes 002 alone.

A later migration adds its own arrays and a case in `schema_definitions_added_by` / `schema_indexes_added_by`, a
`migrations/00N_*.sql` file equal to its generated step, and raises `schema_version`. It never edits an earlier
version's array.

### Positive Consequences

* A fresh database and a 1.0.x one take the same path to the current schema; the upgrade tests compare the two.
* Each table's DDL is in one place and the migration file is checked against it statement for statement.

### Negative Consequences

* A migration that changes an existing table (rather than adding one) cannot be expressed as "what its version adds"
  and needs hand-written statements in its step; none exists yet.

## Pros and Cons of the Options

### Bootstrap the current schema directly

* Good, because a fresh database needs no migration run.
* Bad, because a fresh database and an upgraded one then take different paths, and a difference between them would
  go unnoticed.

### Hand-written DDL for 002

* Good, because it is explicit.
* Bad, because each table's DDL would live twice, and the DDL allowlist would not know the new tables.

## Links

* Builds on [ADR-0224](0224-pre-1-0-migrations-collapse-into-one-frozen-v1-schema.md) and
  [ADR-0216](0216-upgrade-path-is-tested-from-a-forward-only-seam-and-a-real-previous-release-fixture.md)
* Related to [ADR-0776](0776-an-oauth-session-is-a-row-keyed-by-user-and-device-and-the-token-tables-do-not-change.md)
