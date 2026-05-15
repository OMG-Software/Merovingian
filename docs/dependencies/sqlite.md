# SQLite dependency review

This note records the dependency review for SQLite.

## Decision

SQLite is accepted as the embedded database dependency for development,
small-installation, and restart-survival coverage. PostgreSQL remains the
recommended production backend.

## Why it is needed

SQLite gives Merovingian a durable local backend without requiring an external
database server. It supports integration tests that prove runtime state survives
process restart and provides a practical development path for contributors.

## Security boundary

- `sqlite3` and `sqlite3_stmt` handles are RAII-managed inside the SQLite store.
- Statements are prepared and bound through the persistent-store boundary.
- Foreign keys are enabled during startup.
- A busy timeout is configured to avoid unbounded lock waits.
- Runtime summaries do not expose SQLite file paths.

## Maintenance and platform posture

SQLite is available through the supported Linux and BSD package managers and is
required by the Meson build. It should remain isolated to the database backend
module.

## Current limitations

- SQLite is not the target backend for large production deployments.
- Full federation queues, account data, policy rules, push rules, and media blob
  metadata are not fully persisted yet.
