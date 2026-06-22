# migrations/ — SQL Migrations

Migrations run exactly once, in ascending numeric order, and **must never be modified
after they have been applied to any environment**.

## File naming

```
NNN_snake_case_description.sql
```

`NNN` is a zero-padded three-digit integer: `001`, `002`, ..., `010`, `011`, ...
The next migration number is always `max(existing) + 1`.
Current highest: `001`.

Until the project reaches production-ready `v1.0.0`, the checked-in schema
remains a single version-1 initial schema. Fold pre-production table additions
into `001_initial_schema.sql`; do not add `ALTER TABLE` migration files for
pre-beta/pre-1.0 schema churn. After `v1.0.0`, deployed databases become a
compatibility boundary and schema changes must be added as new forward
migration files instead of modifying already-applied migrations.

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

## Safety rules

1. **Never modify an existing production migration.** Write a new one instead.
   Before `v1.0.0`, keep schema churn folded into `001_initial_schema.sql`
   because there are no supported live production databases to upgrade.
2. **Never drop a column or table** without explicit user approval — data loss is irreversible.
3. **Always provide a DEFAULT when adding NOT NULL columns** to existing tables — both SQLite
   and PostgreSQL require this for non-empty tables.
4. **Test on a populated database** before merging: run `python build.py` and verify the server
   starts cleanly against an existing database file.

## Schema source of truth

The canonical schema description lives in `docs/database-persistence.md`.
Update that document whenever a migration changes the schema.
