# src/database/ — Database Module

Manages schema migrations and provides a dual-backend (SQLite / PostgreSQL) persistent store.

## Key files

| File | Responsibility |
|---|---|
| `PersistentStore.cpp` | Abstract store interface — all other modules use this, never the backend directly |
| `SqliteStore.cpp` | SQLite backend — used for development and single-node deployments |
| `PostgresqlStore.cpp` | PostgreSQL backend — used for production |
| `Migration.cpp` | Runs numbered SQL migrations in order; idempotent on re-run |
| `MigrationFiles.cpp` | Parses `migrations/*.sql` for `merovingian-db-migrate --migrations` and the tests; the server runs the C++ catalog |
| `Connection.cpp` | Connection lifecycle and pool management |
| `PreparedStatement.cpp` | Prepared statement wrapper; parameters are always bound, never interpolated |
| `Schema.cpp` | The frozen v1 schema: `core_tables` and `core_indexes`, the `SchemaTableDefinition`/`SchemaIndexDefinition` lists built from them, the `CREATE TABLE`/`CREATE INDEX` SQL, and `current_schema_version()` (ADR-0224: a schema change is a new numbered migration, never an edit to v1) |
| `EventTable.cpp` | `EventTable`, the in-memory mirror of the `events` table with its indexes by event ID, stream order, room and stream order, room and time, and relation target (ADR-0215, ADR-0300, ADR-0430, ADR-0435) |
| `RedactionView.cpp` | Client-facing redaction presentation: adds `redacts` to `m.room.redaction` events and `redacted_because` under `unsigned` of redacted events (CSAZ-11) |
| `PersistentServerSigningKey.cpp` | A stored server signing-key row; wipes the secret on destruction and on overwrite |
| `PostgresqlConnection.cpp` | `PostgresqlConnection`: runs one prepared statement (binary `bytea` parameters) or a `BEGIN`/`COMMIT` transaction on its libpq connection, and judges whether an idle connection may be reused |
| `PostgresqlExecution.cpp` | Module-internal (`detail`, `PostgresqlExecution.hpp`): the libpq result helpers `PostgresqlStore.cpp` and `PostgresqlConnection.cpp` share: redacted connection errors, result status, `load_result_rows` (decodes `bytea` columns), `execute_raw_command` |
| `PostgresqlResultDeleter.cpp` | The `PQclear` deleter for `PostgresqlResultPtr` |
| `PostgresqlConnectionDeleter.cpp`, `SqliteConnectionDeleter.cpp` | The `PQfinish` and `sqlite3_close` deleters for the owning connection pointers |
| `LibraryVersions.cpp` | Reports the SQLite and libpq versions (running and build-time) for the start-up log |
| `RoomAliasTable.cpp` | `RoomAliasTable`, the in-memory mirror of `room_aliases` with indexes by alias, room and creator (ADR-0581) |
| `StateGroupTable.cpp`, `StateGroupEntryTable.cpp`, `EventStateGroupTable.cpp` | The state-group tables with their hash indexes (ADR-0325); their shared rules are in `StateGroupTableSupport.hpp` |
| `RuntimeDatabaseConfig.cpp` | Exposes the live store to the rest of the server |

## Security rules — non-negotiable

1. **Never interpolate values into SQL strings.** Always use prepared statements with bound
   parameters. SQL injection is a critical vulnerability — `PreparedStatement.hpp` enforces this.
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
   hydrate through `remember_audit_event`, never `push_back`. The table is NOT append-only: retention deletes rows older
   than `security.audit_log_retention_days` (ADR-0489), so never order `audit_log` by `ctid` alone (PostgreSQL orders by
   `created_at_ms`, then `ctid`) and name the columns of every insert. `append_audit_event` bounds
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

11. **The to-device queue is bounded in rows, age and bytes, and a batch is prepared in one pass** (ADR-0335,
    ADR-0336). `index_to_device_recipients` gathers the queue of every recipient a batch names with one pass over
    `to_device_messages`; `prepare_to_device_enqueue` then evicts expired, then oldest rows (count, then bytes) from that
    recipient's queue only. The byte total of a queue is never stored: it is summed from the rows when the batch is
    prepared, so it cannot drift from them. Remove in-memory rows with `erase_to_device_rows` (a hash of stream ids),
    never `remove_if` over the victims. `store_account_data` and the capped writers refuse content over
    `max_account_data_row_bytes` (ADR-0339).

12. **A client transaction record is keyed by its device, and only to-device records are pruned** (ADR-0380, ADR-0381).
    `find_client_txn_event_id` takes the device; `prune_to_device_client_txns` deletes records with `room_id` empty and
    rebuilds both position indexes, and must never touch a room-send row (`unsigned.transaction_id` is served from it).
    A key backup version is created by `create_key_backup_version` and deleted by `delete_key_backup_version` with its
    sessions in one transaction (ADR-0384): never reissue a number, and never delete a version row on its own.

## Reloading a room (F-27, ADR-0360)

`reload_room` is `load_room_snapshot` (the database read; touches no row of the store, takes no lock) followed by
`apply_room_snapshot` (the in-memory swap). A caller that shares the store with readers calls the halves itself and takes
its exclusion only around the second: the federation worker does so through `federation_worker::StoreReadGuard`. A
change to what a reload rewrites goes in both the snapshot and the swap, and the swap must keep the state index in step
(`rebuild_state_index`).

## The state index (ADR-0344)

`PersistentStore::state` has two position indexes (`state_position_index`, `state_room_index`) behind
`find_current_state_event_id` and `for_each_room_state_row`. They are trusted only while `state_indexed_rows ==
state.size()` and the row a position names still matches. Every code path that appends to or erases from `state`
calls `note_state_row_appended` or `rebuild_state_index` (the two writers in `PersistentStore.cpp`, `reload_room`,
and both hydration paths); a new one must too. Do not scan `state` for one key or one room in a handler.

## Per-user and per-ID indexes (ADR-0440, ADR-0441)

`account_data_user_index`, `notification_user_index` and `federation_transaction_index` follow the state index's rule:
trusted only while `*_indexed_rows` equals the vector's size and the rows a position names match, else a lookup
scans. Writers call their `ensure_*` first, so they heal; hydration calls `rebuild_account_data_index`,
`rebuild_notification_index` and `rebuild_federation_transaction_index`. Look a user's account data up with
`find_account_data_content` / `for_each_user_account_data`, never by looping `store.account_data`. `store.notifications`
has no order (rows are erased by moving the last into the gap): use `list_notifications_for_user`. One event's
notifications are written by `store_notifications` and its outbound transactions by `store_federation_transactions`,
each in one transaction with the mirror changed after the commit. Tests prove cost with `committed_transaction_count`
and the `*_rows_examined` counters, not time.
## The membership index (ADR-0437)

`PersistentStore::membership_room_index` holds the positions in `memberships` of each room's rows behind
`for_each_room_membership_row`. Like the state index it is trusted only while `membership_indexed_rows ==
memberships.size()` and each position names a row of the room; otherwise a reader scans. Every code path that appends
to `memberships` calls `note_membership_row_appended` (`store_membership`, `apply_membership_projection`, the room
creation writer), every one that erases calls `rebuild_membership_index` (`delete_membership`, `apply_room_snapshot`),
and both hydration paths rebuild it after loading. A row's room never changes in place. A new writer does the same.
`membership_user_index` is the same index keyed by user (`for_each_user_membership_row`, ADR-0609), maintained at the same points and counted in `membership_rows_examined`. Read a user's rows through it, not by scanning `memberships`.
## The relation index (ADR-0430)

`EventTable` lists every row with a usable `content."m.relates_to"` of an aggregated `rel_type` (`m.replace`,
`m.thread`, `m.reference`; never `m.annotation`) under its target event ID and kind
(`relation_child_count`, `for_each_relation_child_newest_first(target, kind, ...)`: one window per kind). It is derived from the row JSON, so `insert`,
`insert_all`, `erase_if`, `modify` (a redaction drops the child) and `clear` keep it current and a writer that
bypasses them does not compile. Status and room are not in the key: the reader judges them. Never scan the
table to find the children of an event.

## Backend selection

The backend is chosen at startup from config (`database.backend = sqlite | postgresql`).
All higher-level modules receive a `PersistentStore&` — they must not downcast to a backend type.

## Migration rules

See `migrations/AGENTS.md` for the migration file format.
Migrations run automatically at startup via `Migration.hpp`; the runner is idempotent. The whole schema is one
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
link `events`/`rooms`); `PersistentStore::redaction_observer` is how the homeserver does, after each stored event and
again when its state group is recorded (`apply_event_state_group`), since a redaction is judged on that state (ADR-0586).
Hydration writes mappings without the observer.

## State-group tables (F-07, F-15, ADR-0325)

`PersistentStore::state_groups`, `state_group_state` and `event_state_groups` are table classes, not vectors: they own their
rows, show them read-only, and keep a hash index over them. Look up with `event_state_groups.state_group_of(event_id)`,
`state_groups.find(id)` and `state_group_state.entries_of(id)` (or `find_event_state_group`, `find_state_group`,
`find_state_group_state_event_id` for one key, `read_state_group_full_state`); never loop over a whole table to find a key. Write only through `insert`, `insert_all`,
`assign`, `erase_if` and `clear`, which keep the index right; a writer that bypasses them does not compile. Hydration and
`reload_room` use `insert_all` / `erase_if`. The tables have no lock: a reader needs exclusion from writers (in main,
`runtime.mutex`), and a view or `string_view` they return is valid only until the next write.

## Room aliases (F-03, ADR-0581)

`PersistentStore::room_aliases` is a `RoomAliasTable`, not a vector: it owns the rows, shows them read-only and keeps
indexes by alias, by room and by creator. Look up with `find_room_alias` / `room_aliases.find`, list a room aliases with
`aliases_of_room`, count with `count_for_room` and `count_for_creator`; never loop the table to find one key or one room.
Write only through `insert`, `erase`, `reassign` and `clear` (hydration uses `insert`); an erase moves the last row into
the hole, so row order means nothing. The table has no lock: a reader needs exclusion from writers (`runtime.mutex`).

## Credential tables (F-08, ADR-0325, ADR-0488)

`PersistentStore::access_tokens` and `refresh_tokens` are `CredentialTable<Row>` (header-only,
`include/merovingian/database/CredentialTable.hpp`), not vectors: they own their rows, show them read-only and index them
by token hash, by (user ID, device ID), by user and, for refresh tokens, by predecessor hash. The hash and predecessor
indexes are DIGEST indexes (ADR-0488): keyed on `std::hash` of the stored hash, they only narrow, and every candidate is
confirmed with `crypto::constant_time_equal` (`src/auth/AGENTS.md` rule 3). Never key a map on the hash string, never answer
from the index alone, never scan after a miss. Look up with `find`/`contains`/`has_unrevoked_*`, revoke with `revoke_hash`,
`revoke_for_user`, `revoke_for_device`, `revoke_for_user_except_device` and `revoke_with_predecessor`, add with `insert`
(hydration too) and remove with `erase` (the last row fills the hole, so order means nothing) or `erase_if` (the retention
sweep; it rebuilds the indexes). A row's hash, user, device and predecessor never change after `insert`; `revoked` flips only
through the revoke methods, and only one way. `rows_examined()` is an `ExaminedRows` counter of every row a method visited, for
tests that prove cost. `erase_for_device` removes a device's rows through the device index and
`oldest_retired_beyond` names the retired refresh rows past a count, oldest `issued_at_ms` first, never an unrevoked one
(ADR-0590); `store_device_and_access_token(..., true)` and `rotate_device_credentials` delete and insert in one transaction and
change memory only after the commit. The tables have no lock: `runtime.mutex` serialises them.

## Retained PDUs (F-18, ADR-0326)

`PersistentStore::deferred_pdu_awaits` indexes each retained PDU under the event IDs it is missing
(`find_missing_event_references`, also what ingestion backfills by). `upsert_deferred_pdu` and `remove_deferred_pdu` keep it
current; hydration calls `rebuild_deferred_pdu_awaits`. Find the rows waiting for an event with
`take_deferred_pdus_awaiting`; never search `pdu_json` for an ID.

## A room's newest `origin_server_ts` (ADR-0497)

`EventTable::room_latest_origin_server_ts(room_id)` is the greatest positive `origin_server_ts` among the room's rows of every
status (sliding sync's room `timestamp`). `insert` and `insert_all` raise it, `erase_if` and `modify` recompute the affected
rooms from their rows, `clear` and `extract` empty it, so a writer that bypasses them does not compile. Do not parse a room's
events to find it.

## PersistentStore's own mutexes (ADR-0517)

`statement_capture_mutex` and `server_signing_keys_mutex` are `core::CopyableMutex` members held by value. A copy of the
store gets fresh, unlocked mutexes, so copy a store only while no other thread is using it. The copy constructor and copy
assignment are defaulted (ADR-0523): a copy carries every member and index. Never go back to a hand-written member list;
one missed `state_transitions` and its index for months. A member that must not be copied gets its own copy semantics,
as `core::CopyableMutex` has. No production code copies a store; only tests do.
