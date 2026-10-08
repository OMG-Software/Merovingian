# src/database/ — Database Module

Manages schema migrations and provides a dual-backend (SQLite / PostgreSQL) persistent store.

## Key files

| File | Responsibility |
|---|---|
| `persistent_store.cpp` | Abstract store interface — all other modules use this, never the backend directly |
| `sqlite_store.cpp` | SQLite backend — used for development and single-node deployments |
| `postgresql_store.cpp` | PostgreSQL backend — used for production |
| `migration.cpp` | Runs numbered SQL migrations in order; idempotent on re-run |
| `migration_files.cpp` | Loads migration SQL from `migrations/` at build time |
| `connection.cpp` | Connection lifecycle and pool management |
| `statement.cpp` | Prepared statement wrapper; parameters are always bound, never interpolated |
| `schema.cpp` | Schema introspection helpers |
| `runtime_database.cpp` | Exposes the live store to the rest of the server |

## Security rules — non-negotiable

1. **Never interpolate values into SQL strings.** Always use prepared statements with bound
   parameters. SQL injection is a critical vulnerability — `statement.hpp` enforces this.
2. **Never log raw query parameters** that may contain tokens, passwords, or PII.
3. **Schema changes go in `migrations/`**, not in ad-hoc `ALTER TABLE` calls in code.
4. **Every write to a `BLOB` column sets `BoundValue::binary`.** PostgreSQL then binds the
   bytes in libpq's binary format; any other way truncates at a NUL or rejects non-UTF-8.
   Reads need nothing per column: `load_result_rows` decodes every `bytea` result column
   (`PQftype`). The columns are `media_blobs.bytes` and `server_signing_keys.secret_key`.
5. **Never retain committed statements in production.** `PersistentStore::captured_statements`
   is empty and disabled unless a test calls `enable_statement_capture`; it is bounded and drops
   the oldest entry first. A committed statement's bound parameters include password and token
   hashes, so keeping them would leave those hashes in process memory for its whole life.
6. **In-memory mirrors of append-only tables are bounded windows.** `PersistentStore::audit_log`
   holds the newest `max_in_memory_audit_events` rows; append through `append_audit_event` and
   hydrate through `remember_audit_event`, never `push_back`. `append_audit_event` bounds
   `actor`, `target` and `reason` to 255 bytes on a UTF-8 boundary (`bounded_utf8`).

## Backend selection

The backend is chosen at startup from config (`database.engine = sqlite | postgresql`).
All higher-level modules receive a `PersistentStore&` — they must not downcast to a backend type.

## Migration rules

See `migrations/AGENTS.md` for the migration file format.
Migrations run automatically at startup via `migration.hpp`; the runner is idempotent.

## Key docs

- `docs/database-persistence.md` — schema reference, store interface, migration policy

## Redaction state (CSAZ-11)

`PersistentStore::redactions` (which redaction events name which target, which are still withheld from clients, which
was applied to which target) is derived from `events` and never persisted in a table of its own: `rebuild_redaction_state`
re-derives it after hydration and the homeserver's startup reconciliation re-applies. What is durable is the redacted
JSON of the target (`replace_event_json`), so no migration. The database module does not judge redactions (it cannot
link `events`/`rooms`); `PersistentStore::redaction_observer` is how the homeserver does, after each stored event.
