# Database persistence

This capability note describes the project-owned database persistence boundary,
the SQLite runtime backend, and the remaining work before PostgreSQL-backed
production operation.

## Included now

- Prepared statement representation.
- Bound parameter representation with sensitivity metadata.
- Statement-name validation.
- Conservative SQL-shape validation.
- Redacted bound-parameter summaries.
- Database executor interface.
- Validated execution helper that rejects invalid statements before they reach an executor.
- Migration step and migration plan models.
- Contiguous upgrade and explicit downgrade migration-plan validation.
- Initial schema table inventory covering the Matrix storage areas from the project plan.
- Media metadata schema migration from version `1` to version `2`.
- SQLite RAII wrappers around database connections and prepared statements.
- SQLite current-schema bootstrap for new database files.
- SQLite row hydration for users, devices, access tokens, rooms, memberships,
  events, current state, media metadata, remote media metadata, audit events,
  and admin actions.
- Write-through SQLite persistence behind the existing store mutation helpers.
- Runtime hydration for users, sessions, rooms, memberships, events, and client
  device listings.
- Unit coverage for statement validation, executor gating, redaction, migration planning, and schema inventory.
- Integration coverage proving SQLite users, sessions, rooms, and events survive
  a homeserver runtime restart.

## Security posture

The homeserver runtime can now use SQLite for local persisted state when
`database.backend=sqlite` is configured. Dependency-specific SQLite types remain
inside the database module and do not leak into homeserver services.

The boundary provides these guarantees:

- Application code submits named prepared-statement shapes, not ad hoc SQL execution requests.
- Invalid statement names fail before reaching the executor.
- Obvious multi-statement/comment-shaped SQL is rejected at the boundary.
- Sensitive parameter values can be summarized without leaking the value.
- Migration plans are contiguous and direction-aware.
- Core table inventory is explicit and test-covered.
- Media rows include hash algorithm, digest, quarantine state, and removal state before runtime media writes are accepted.
- Fresh SQLite database files are created with the current schema and recorded
  migration metadata.
- Existing SQLite database files are validated before runtime state is hydrated.
- Auth and room mutations fail the request when required persistent writes fail.

## Deliberately not included

These remain deferred:

- libpq dependency integration.
- Live PostgreSQL connection management.
- PostgreSQL query execution.
- Transaction handling.
- Runtime/migration role separation.
- Physical SQL migration files.
- PostgreSQL-backed users, devices, tokens, rooms, events, media, federation,
  policy, or audit storage.
- SQLite-backed federation queues, policy rules, account data, push rules,
  E2EE keys, and full media repository blob metadata hydration.
- Integration tests against a running PostgreSQL instance.

## Next starting points

1. Add transaction helpers so multi-row runtime mutations commit atomically.
2. Add dependency review documentation for libpq.
3. Add RAII wrappers around PostgreSQL connections and results.
4. Add migration-file loading and offline migrator tool scaffolding.
5. Add SQL migration integration tests with temporary SQLite and PostgreSQL databases.
