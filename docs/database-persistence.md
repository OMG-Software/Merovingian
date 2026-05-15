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
- Initial schema table inventory covering the Matrix storage areas from the project plan.
- Media metadata schema migration from version `1` to version `2`.
- E2EE key storage schema migration from version `2` to version `3`.
- SQLite RAII wrappers around database connections and prepared statements.
- SQLite current-schema bootstrap for new database files.
- SQLite row hydration for users, devices, access tokens, rooms, memberships,
  events, current state, server signing keys, event DAG rows, event signatures,
  E2EE key state, media metadata, remote media metadata, audit events, and admin
  actions.
- Write-through SQLite persistence behind the existing store mutation helpers.
- Transaction-aware persistent-store commits with SQLite rollback support.
- Atomic helpers for multi-row login, room creation, and state-event writes.
- SQLite hydration fails closed when a row query cannot be prepared or stepped
  to completion.
- SQLite connections use a non-zero busy timeout for short-lived lock
  contention.
- `libpq` dependency review and a PostgreSQL RAII connection/result wrapper.
- PostgreSQL current-schema bootstrap, row hydration, and write-through
  transaction execution when a URI file is explicitly configured.
- Durable persistent-store helpers for device keys, one-time keys, fallback
  keys, cross-signing keys, key signatures, key backup versions, and key backup
  sessions.
- Physical migration-file loading for SQL files with explicit metadata and
  statement names.
- Offline `merovingian-db-migrate` planning scaffold.
- Database `runtime` and `migration` role separation.
- Runtime hydration for users, sessions, rooms, memberships, events, and client
  device listings.
- Runtime event writes persist previous-event edges, auth-event edges, and
  Matrix event signatures in the same transaction as the event row.
- Unit coverage for statement validation, executor gating, redaction, migration
  planning, and schema inventory.
- Migration-plan validation coverage uses explicit hand-built plans, while
  current-schema upgrade coverage separately tracks schema-version bumps.
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
- Existing SQLite database files apply pending project-owned migrations before
  runtime state is hydrated.
- Auth and room mutations fail the request when required persistent writes fail.
- Device/token, room/membership, and event/current-state mutations are committed
  atomically before in-memory runtime state is updated.
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

- Full PostgreSQL integration tests against a running temporary server.
- Runtime/migration role grants enforced by actual database users.
- PostgreSQL-backed federation queues, policy, account data, push rules, and
  full media repository blob metadata hydration.
- SQLite-backed federation queues, policy rules, account data, push rules, and
  full media repository blob metadata hydration.

## Next starting points

1. Add full SQL migration integration tests with temporary SQLite and
   PostgreSQL databases.
2. Enforce runtime/migration role grants with separate PostgreSQL users.
3. Extend transaction helpers across federation queues, policy actions, and
   media metadata once those rows are runtime-wired.
4. Persist account data, push rules, federation queues, and media blob
   metadata.
