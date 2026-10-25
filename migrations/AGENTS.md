# migrations/ — SQL Migrations

Migrations run exactly once, in ascending numeric order, and **must never be modified
after they have been applied to any environment**.

## The v1 schema (ADR-0224)

In 0.12.47 every pre-1.0 migration was collapsed into one: `001_initial_schema.sql`,
schema version `1`. It creates all 62 tables in their final shape and the four
secondary indexes (`event_edges_prev_event_id`, `idx_to_device_messages_recipient_age`,
`idx_deferred_pdus_room_id`, `idx_media_pending_uploads_owner`). There are no upgrades
from before it: a database whose `schema_migrations` ledger holds a row this build does
not have, such as the rows 2 to 26 every build up to 0.12.46 wrote, is refused at open
(`schema_ledger_is_known`) and must be recreated.

The file is the frozen record of what the build runs. The server never reads it; the
C++ step `initial_schema_migration()` in `src/database/migration.cpp`, generated from
`core_tables` and `core_indexes` in `src/database/schema.cpp`, is what runs. The unit
test "Checked-in migrations hold exactly the v1 step this build runs" requires the two
to match statement for statement.

- **Until 1.0.0 is cut**, a schema change edits `core_tables`/`core_indexes` and this
  file together, in the same commit. Regenerate the file rather than hand-editing it.
- **From 1.0.0, v1 is frozen.** Never edit `001_initial_schema.sql`, and never change
  `core_tables`/`core_indexes` in a way that changes what v1 creates. A schema change is
  a new migration: `002_<name>.sql`, plus its upgrade step in `upgrade_migration_catalog()`
  and its downgrade at the front of `downgrade_migration_catalog()`. The first one must
  also make `initial_schema_definitions()` keep returning the v1 shape while
  `current_schema_definitions()` gains the change (today both return the same registry).
- Never rename a step or reuse a version number: the ledger check identifies a step by
  both.

## File naming

```
NNN_snake_case_description.sql
```

`NNN` is a zero-padded three-digit integer: `001`, `002`, ..., `010`, `011`, ...
The next migration number is always `max(existing) + 1`.
Current highest: `001`.

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
- The v1 file names each table statement `create_<table>` and each index statement
  `create_<index>`, and quotes table names in `CREATE TABLE`, exactly as the build's
  generated DDL does

## Federation worker classification

Every table a migration creates must be classified for the federation worker: in
`federation_worker_table_allowlist`, in `tests/unit/test_worker_db_uri.cpp`'s set of
tables the worker never reads, or as ungated infrastructure. That test parses every
`CREATE TABLE` in `migrations/*.sql` and fails on an unclassified or stale name, so a new
table is classified in the commit that adds it.

## Safety rules

1. **Never modify an existing production migration.** Write a new one instead. Before
   `v1.0.0` the only migration is `001_initial_schema.sql`, which changes in place
   (see above); from `v1.0.0` it is frozen like any other.
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
