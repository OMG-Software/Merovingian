# migrations/ — SQL Migrations

Migrations run exactly once, in ascending numeric order, and **must never be modified
after they have been applied to any environment**.

## The v1 schema (ADR-0224)

In 0.12.47 every pre-1.0 migration was collapsed into one: `001_initial_schema.sql`,
schema version `1`. It creates all 64 tables in their final shape and the nine
secondary indexes (`event_edges_prev_event_id`, `idx_to_device_messages_recipient_age`,
`idx_deferred_pdus_room_id`, `idx_media_pending_uploads_owner`, `idx_events_room_id`,
`idx_state_groups_room_id`, `idx_access_tokens_user_device`, `idx_refresh_tokens_user_device`,
`idx_refresh_tokens_predecessor`). There are no upgrades
from before it: a database whose `schema_migrations` ledger holds a row this build does
not have, such as the rows 2 to 26 every build up to 0.12.46 wrote, is refused at open
(`schema_ledger_is_known`) and must be recreated.

The file is the frozen record of what the build runs. The server never reads it; the
C++ step `initial_schema_migration()` in `src/database/Migration.cpp`, generated from
`core_tables` and `core_indexes` in `src/database/Schema.cpp`, is what runs. The unit
test "Checked-in migrations hold exactly the v1 step this build runs" requires the two
to match statement for statement.

- **v1 is frozen (1.0.0 is cut).** The pre-1.0 rule, that a schema change edited
  `core_tables`/`core_indexes` and this file together, no longer applies. Never edit `001_initial_schema.sql`, and never change
  `core_tables`/`core_indexes` in a way that changes what v1 creates. A schema change is
  a new migration: `00N_<name>.sql`, plus its upgrade step in `upgrade_migration_catalog()`
  and its downgrade at the front of `downgrade_migration_catalog()`.

## Migration 002: the OAuth 2.0 tables (1.1.0, ADR-0776, ADR-0778)

`002_oauth_tables.sql` creates `oauth_clients`, `oauth_sessions` and `idx_oauth_sessions_client_id`. It is the
first migration after v1, so it also split the schema registry by version (ADR-0778): `Schema.cpp` keeps one pair of
arrays per version (`core_tables`/`core_indexes` for v1, `oauth_tables`/`oauth_indexes` for v2), and
`schema_definitions_added_by(version)` / `schema_indexes_added_by(version)` return what a version adds.
`initial_schema_definitions()` is version 1 only and `current_schema_definitions()` every version up to
`current_schema_version()`. Each step is generated from what its version adds (`oauth_tables_migration()`), and the
bootstraps build version 1 only, so a fresh database runs 002 exactly as an upgraded 1.0.x one does. The unit test
"Checked-in migrations hold exactly the steps this build runs" compares every file to its catalog step.

A later migration that adds tables does the same: new arrays, a case in both `*_added_by` functions, a step built
with `schema_step_creating` and its downgrade with `schema_step_dropping`, a file equal to the step, a higher
`schema_version`, and the new tables classified for the worker. It never edits an earlier version's arrays.
`merovingian-db-migrate --plan A B --migrations DIR` takes only the files with a version in (A, B].
- Never rename a step or reuse a version number: the ledger check identifies a step by
  both.

## File naming

```
NNN_snake_case_description.sql
```

`NNN` is a zero-padded three-digit integer: `001`, `002`, ..., `010`, `011`, ...
The next migration number is always `max(existing) + 1`.
Current highest: `002`.

## File format

```sql
-- merovingian-migration version=N name=snake_case_description direction=upgrade
-- statement snake_case_statement_name
SQL STATEMENT
-- statement next_statement_name
NEXT SQL STATEMENT
```

- `version=N` matches the numeric prefix (no leading zeros in the integer, e.g. `version=5` for `005_...`)
- Each statement preceded by `-- statement <name>` on its own line
- Statement names must be unique within the file and descriptive (`events_add_stream_ordering`, not `stmt1`)
- No trailing semicolons — the migration runner adds them
- The v1 and 002 files name each table statement `create_<table>` and each index statement
  `create_<index>`, and quote table names in `CREATE TABLE`, exactly as the build's
  generated DDL does

## Federation worker classification

Every table a migration creates must be classified for the federation worker: in
`federation_worker_table_allowlist`, in `tests/unit/test_worker_table_load_profile.cpp`'s set of
tables the worker never reads, or as ungated infrastructure. That test parses every
`CREATE TABLE` in `migrations/*.sql` and fails on an unclassified or stale name, so a new
table is classified in the commit that adds it.

## Safety rules

1. **Never modify an existing production migration.** Write a new one instead. `001_initial_schema.sql`
   is frozen like any other migration (see above).
2. **Never drop a column or table** without explicit user approval — data loss is irreversible.
3. **Always provide a DEFAULT when adding NOT NULL columns** to existing tables — both SQLite
   and PostgreSQL require this for non-empty tables.
4. **Put an added column where `ADD COLUMN` would.** Some writes are positional
   (`INSERT INTO access_tokens VALUES (...)`), so a column's position is part of the
   schema.
5. **Test on a populated database** before merging: run `python build.py` and verify the server
   starts cleanly against an existing database file.

## Schema source of truth

The canonical schema description lives in `docs/database-persistence.md`.
Update that document whenever a migration changes the schema.
