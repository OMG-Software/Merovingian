# Database persistence

This capability note describes the project-owned database persistence boundary,
the SQLite runtime backend, the initial PostgreSQL/libpq boundary, and the
remaining work before PostgreSQL-backed production operation.

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
- Initial schema deployed at version `1` in its final shape: 42 core
  tables covering every Matrix storage area from the project plan. There
  are no live databases to upgrade, so historical per-version migrations
  have been collapsed into the single `initial_schema` step. Future schema
  changes will add their own forward migrations.
- SQLite RAII wrappers around database connections and prepared statements.
- SQLite current-schema bootstrap for new database files.
- SQLite row hydration for users, devices, access tokens, rooms, memberships,
  refresh tokens, events (with depth), current state, server signing keys (with
  server_name), event DAG rows, event signatures, E2EE key state, media
  metadata, durable media blobs, remote media metadata, account data, policy
  rules, audit events, and admin actions.
- Write-through SQLite persistence behind the existing store mutation helpers.
- Transaction-aware persistent-store commits with SQLite rollback support.
- Atomic helpers for multi-row login, room creation, and state-event writes.
- Persistent helpers for refresh-token rotation, global/device access-token
  and refresh-token revocation, device display-name updates, and device
  deletion.
- SQLite hydration fails closed when a row query cannot be prepared or stepped
  to completion.
- SQLite connections use a non-zero busy timeout for short-lived lock
  contention.
- `libpq` dependency review and a PostgreSQL RAII connection/result wrapper.
- PostgreSQL current-schema bootstrap, row hydration, and write-through
  transaction execution when a URI file is explicitly configured.
- Durable persistent-store helpers for device keys, one-time keys, fallback
  keys, cross-signing keys, key signatures, key backup versions, and key
  backup sessions.
- Physical migration-file loading for SQL files with explicit metadata and
  statement names.
- Offline `merovingian-db-migrate` planning scaffold.
- Database `runtime` and `migration` role separation.
- Runtime hydration for users, sessions, rooms, memberships, events, client
  device listings, and durable media repository blobs.
- Runtime event writes persist previous-event edges, auth-event edges, and
  Matrix event signatures in the same transaction as the event row.
- Event depth column persisted alongside events so depth survives restarts.
- Server signing keys scoped by server_name with composite primary key.
- Runtime trust-and-safety report/review paths append durable policy audit rows
  and admin action rows.
- Policy rule and media blob helpers upsert durable rows and hydrate them after
  SQLite/PostgreSQL reopen.
- Unit coverage for statement validation, executor gating, redaction, migration
  planning, and schema inventory.
- Migration-plan validation coverage uses explicit hand-built plans, while
  current-schema upgrade coverage separately tracks schema-version bumps.
- Integration coverage proving SQLite users, sessions, rooms, and events survive
  a homeserver runtime restart.
- Live PostgreSQL integration coverage: a dedicated GitHub Actions workflow
  (`.github/workflows/postgres-integration.yml`) starts a PostgreSQL 16
  service, provisions a `merovingian_migration` role with DDL grants and a
  `merovingian_runtime` role with table-level DML grants, and runs the
  live integration scenarios at
  `tests/integration/test_postgresql_persistence_flow.cpp`. Scenarios
  assert: schema is bootstrapped to `current_schema_version`, previously
  persisted rows survive a close/reopen, and a runtime-role session is
  denied DDL.
- PostgreSQL role helpers (`set_postgresql_role`, `reset_postgresql_role`,
  `current_postgresql_user`) in
  [postgresql_store.hpp](../include/merovingian/database/postgresql_store.hpp)
  let runtime callers switch identities inside a single connection. Role
  names are validated against PostgreSQL identifier shape (alphanumeric
  plus underscore, ≤ 63 chars) before being interpolated into the
  `SET ROLE` statement, so the API is safe to call with operator-supplied
  role names.

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
- Media rows include hash algorithm, digest, quarantine state, removal state,
  and durable blob references before runtime media writes are accepted.
- Fresh SQLite database files are created with the current schema and recorded
  migration metadata.
- Existing SQLite database files apply pending project-owned migrations before
  runtime state is hydrated.
- Auth and room mutations fail the request when required persistent writes fail.
- Device/token, refresh-token, room/membership, and event/current-state
  mutations are committed before in-memory runtime state is updated.
- Signed event DAG rows are committed before the runtime room timeline is
  updated.
- Multi-row runtime mutations commit through one backend transaction so partial
  login, room, or state-event writes are rolled back.
- PostgreSQL connection strings are accepted only in explicit URI or libpq
  key/value form, and password material is redacted from summaries.
- Runtime startup requires `database.role=runtime`; offline migration planning
  requires `database.role=migration`.

## Deliberately not included

These remain deferred:

- PostgreSQL-backed federation queues, policy rules, push rules, and
  full media repository blob metadata hydration.
- SQLite-backed federation queues, policy-rule management, push rules, and
  full media repository blob metadata hydration.

## Next starting points

1. Extend transaction helpers across federation queues, policy actions, and
   media metadata once those rows are runtime-wired.
2. Persist push rules, federation queues, and media blob metadata.
