# src/database/ — Database Module

Manages schema migrations and provides a dual-backend (SQLite / PostgreSQL) persistent store.

## Key files

| File | Responsibility |
|---|---|
| `persistent_store.cpp` | Abstract store interface — all other modules use this, never the backend directly |
| `sqlite_store.cpp` | SQLite backend — used for development and single-node deployments |
| `postgresql_store.cpp` | PostgreSQL backend — used for production |
| `migration.cpp` | Runs numbered SQL migrations in order; idempotent on re-run |
| `migration_files.cpp` | Parses `migrations/*.sql` for `merovingian-db-migrate --migrations` and the tests; the server runs the C++ catalog |
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
   `actor`, `target` and `reason` to 255 bytes on a UTF-8 boundary (`observability::bounded_utf8`).

7. **Persisted writes lease a pooled connection; nothing else opens one per write.** `commit_persistent_transaction`
   goes through the store's `ConnectionPool` (at most `database.pool_size` in use, ADR-0154). Hold a lease for exactly
   one transaction and never take another lease while holding one, or writers can deadlock waiting for each other.
   A PostgreSQL connection is reused only while idle with nothing to read on its socket.

8. **Nothing in this process opens a SQLite database file except SQLite** (ADR-0157). Closing any descriptor of a
   file releases every POSIX lock the process holds on it, so a check that opens and closes the database (for its
   owner, type, size or header, or to chmod it) silently drops another connection's write lock, and another process
   then rolls back a live transaction's journal as hot. Check by name (`fstatat` with `AT_SYMLINK_NOFOLLOW`) or read
   through SQLite's own handle (`SQLITE_FCNTL_FILE_POINTER`).

9. **Read-only SQLite reads prepare through `prepare` and step through `first_step`** (ADR-0159). A writer that
   commits between SQLite's two hot-journal checks makes a read-only connection fail with `SQLITE_READONLY_ROLLBACK`
   at once, skipping the busy handler. Those helpers, and the open-time pragmas, retry that result for up to 2 s. Do
   not hold one read transaction across a whole-store load to avoid it: main's writers wait at most 5 s for it.

10. **A read that combines several tables into one picture of a room runs in one read transaction** (ADR-0161):
    `SqliteReadTransaction` on SQLite, `REPEATABLE READ READ ONLY` on PostgreSQL. `reload_room` does; separate
    autocommit reads let a commit between them give the worker state naming an event its snapshot lacks. The snapshot
    carries the room's state groups, their entries and its events' group mappings too: federation reads fail closed on an
    event with no group, so a new table a worker-served read depends on must be added to the snapshot and `reload_room`.

## Backend selection

The backend is chosen at startup from config (`database.engine = sqlite | postgresql`).
All higher-level modules receive a `PersistentStore&` — they must not downcast to a backend type.

## Migration rules

See `migrations/AGENTS.md` for the migration file format.
Migrations run automatically at startup via `migration.hpp`; the runner is idempotent. The whole schema is one
v1 step (ADR-0224), frozen from 1.0.0. Both stores refuse a ledger that names a migration this build does not have
(`schema_ledger_is_known`) before migrating or hydrating anything, and the PostgreSQL bootstrap, like every migration,
runs as `database.migration_role` when one is configured.

## Key docs

- `docs/database-persistence.md` — schema reference, store interface, migration policy

## Redaction state (CSAZ-11)

`PersistentStore::redactions` (which redaction events name which target, which are still withheld from clients, which
was applied to which target) is derived from `events` and never persisted in a table of its own: `rebuild_redaction_state`
re-derives it after hydration and the homeserver's startup reconciliation re-applies. What is durable is the redacted
JSON of the target (`replace_event_json`), so no migration. The database module does not judge redactions (it cannot
link `events`/`rooms`); `PersistentStore::redaction_observer` is how the homeserver does, after each stored event.
