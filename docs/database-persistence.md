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
- Initial schema deployed at version `1` in its final shape: 45 core
  tables covering every Matrix storage area from the project plan. There
  were no live databases at that time, so historical per-version migrations
  were collapsed into the single `initial_schema` step. Once live
  pre-production deployments existed, subsequent schema changes started
  receiving their own numbered migration files; schema version `2` adds the
  `sync_stream_watermark` table via `migrations/002_sync_stream_watermark.sql`.
  After the project reaches production-ready `v1.0.0`, every schema change
  must add a forward migration and keep deployed databases compatible.
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
- `set_user_account_state` updates the `users` table `suspended`/`locked`
  columns and mirrors the new state into the in-memory `PersistentUser`, used by
  the admin lock/suspend endpoints.
- `restore_tokens_for_device` re-activates a single device's access and refresh
  tokens (setting `revoked = false`) after a user-wide revocation, so a password
  change with `logout_devices: true` can revoke every other device while keeping
  the caller's session.
- Access and refresh token rows carry an `expires_at` column (`TEXT NOT NULL
  DEFAULT ''`, empty = no expiry / legacy) folded into the version-1 initial
  schema. `store_access_token`, `store_refresh_token`, and
  `store_device_and_access_token` bind the epoch-millis text of the token's
  `expires_at`, and SQLite/PostgreSQL hydration parse it back into the
  `PersistentAccessToken` / `PersistentRefreshToken` `expires_at` field
  (`std::optional<system_clock::time_point>`, `nullopt` for empty). The runtime
  enforces expiry at the session/refresh lookup rather than at the store layer.
- Token-hash equality at the store layer uses constant-time comparison
  (`crypto::constant_time_equal`, backed by `sodium_memcmp`) for the access and
  refresh token lookups, so a database-equivalent match does not branch on the
  fixed-length hash bytes.
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
  statement names; the checked-in pre-production migration directory now
  contains the version-1 `initial_schema` create-table file and numbered
  migrations such as `002_sync_stream_watermark.sql`.
- `sync_stream_watermark` table stores the highest allocated `sync_stream_id`
  and is updated by `database::allocate_sync_stream_id()` before the ID is
  used for ephemeral events such as typing notifications and read receipts. This
  prevents the monotonic sync stream counter from rolling back across restarts.
- `database::restore_sync_stream_id()` writes the highest `sync_stream_id` found
  in durable rows (account data, to-device messages, device-list changes,
  presence) into the watermark on startup, so fresh upgrades start from the
  maximum persisted value rather than the table default.
- `/sync` calls `database::ensure_sync_stream_id_ahead_of()` when the client's
  `since` token is ahead of the server's counter. This recovers live deployments
  whose counter rolled back below a stored token (for example, when the watermark
  table did not yet exist and ephemeral typing/receipt events advanced the
  in-memory counter), ensuring the next ephemeral event gets an ID the client
  will accept.
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

- Client transaction-idempotency dedup via the version-1 `client_txn_ids` table.
  Keyed on `(user_id, room_id, event_type, txn_id)`; `room_id` is empty string
  for to-device sends. `event_id` stores the assigned event ID for room sends and
  is empty for to-device entries. Both SQLite and PostgreSQL hydrate rows on
  startup. Handlers check the table before processing and store the result after
  a successful send, allowing clients to safely retry `PUT /rooms/{roomId}/send`
  and `PUT /sendToDevice` requests.

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
