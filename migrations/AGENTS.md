# migrations/ — SQL Migrations

Migrations run exactly once, in ascending numeric order, and **must never be modified
after they have been applied to any environment**.

## File naming

```
NNN_snake_case_description.sql
```

`NNN` is a zero-padded three-digit integer: `001`, `002`, ..., `010`, `011`, ...
The next migration number is always `max(existing) + 1`.
Current highest: `006`.

Schema version `2` introduced the `sync_stream_watermark` table via
`002_sync_stream_watermark.sql` to support live pre-production deployments that
must upgrade in place. Schema version `3` adds the analogous
`event_stream_watermark` table via `003_event_stream_watermark.sql` so the
timeline stream_ordering counter survives restarts. Schema version `4` adds
the `state_transitions` table via `004_state_transitions.sql` so the server can
populate `unsigned.replaces_state` when serving state events to clients. Schema
version `5` (`005_backfill_state_transitions.sql`) is data-only and backfills
the `state_transitions` rows for pre-existing rooms; it adds no tables. Schema
version `6` adds the `account_threepids` table via `006_account_threepids.sql`
so durable 3PID bindings (medium/address, optional country and identity server,
validation/bound timestamps) survive restarts. After
`v1.0.0`, deployed databases become a strict compatibility boundary and schema
changes must be added as new forward migration files instead of modifying
already-applied migrations.

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
