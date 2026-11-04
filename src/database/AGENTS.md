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
| `state_group_tables.cpp` | `StateGroupTable`, `StateGroupEntryTable`, `EventStateGroupTable`: the state-group tables with their hash indexes (ADR-0325) |
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
calls `note_state_row_appended` or `rebuild_state_index` (the two writers in `persistent_store.cpp`, `reload_room`,
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
## The relation index (ADR-0430)

`EventTable` lists every row with a usable `content."m.relates_to"` of an aggregated `rel_type` (`m.replace`,
`m.thread`, `m.reference`; never `m.annotation`) under its target event ID and kind
(`relation_child_count`, `for_each_relation_child_newest_first(target, kind, ...)`: one window per kind). It is derived from the row JSON, so `insert`,
`insert_all`, `erase_if`, `modify` (a redaction drops the child) and `clear` keep it current and a writer that
bypasses them does not compile. Status and room are not in the key: the reader judges them. Never scan the
table to find the children of an event.

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

## State-group tables (F-07, F-15, ADR-0325)

`PersistentStore::state_groups`, `state_group_state` and `event_state_groups` are table classes, not vectors: they own their
rows, show them read-only, and keep a hash index over them. Look up with `event_state_groups.state_group_of(event_id)`,
`state_groups.find(id)` and `state_group_state.entries_of(id)` (or `find_event_state_group`, `find_state_group`,
`read_state_group_full_state`); never loop over a whole table to find a key. Write only through `insert`, `insert_all`,
`assign`, `erase_if` and `clear`, which keep the index right; a writer that bypasses them does not compile. Hydration and
`reload_room` use `insert_all` / `erase_if`. The tables have no lock: a reader needs exclusion from writers (in main,
`runtime.mutex`), and a view or `string_view` they return is valid only until the next write.

## Retained PDUs (F-18, ADR-0326)

`PersistentStore::deferred_pdu_awaits` indexes each retained PDU under the event IDs it is missing
(`find_missing_event_references`, also what ingestion backfills by). `upsert_deferred_pdu` and `remove_deferred_pdu` keep it
current; hydration calls `rebuild_deferred_pdu_awaits`. Find the rows waiting for an event with
`take_deferred_pdus_awaiting`; never search `pdu_json` for an ID.
