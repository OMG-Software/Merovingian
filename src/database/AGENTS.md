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

## Backend selection

The backend is chosen at startup from config (`database.engine = sqlite | postgresql`).
All higher-level modules receive a `PersistentStore&` — they must not downcast to a backend type.

## Migration rules

See `migrations/AGENTS.md` for the migration file format.
Migrations run automatically at startup via `migration.hpp`; the runner is idempotent.

## Key docs

- `docs/database-persistence.md` — schema reference, store interface, migration policy
