# Database persistence

This capability note describes the project-owned database persistence boundary,
the SQLite runtime backend, the initial PostgreSQL/libpq boundary, and the
remaining work before PostgreSQL-backed production operation.

The deployed configuration parser accepts only `postgresql` and `sqlite`.
PostgreSQL startup fails when its URI file is missing, unreadable, or empty; it
never substitutes a process-local store. `DatabaseBackend::memory` is an
explicit programmatic backend for tests only and is not a valid config-file
value. Test fixtures that do not exercise persistence select it through
`tests/support/in_memory_database_config.hpp`.

## Included now

- Prepared statement representation.
- Bound parameter representation with sensitivity metadata.
- Statement-name validation.
- Conservative SQL-shape validation.
- Redacted bound-parameter summaries.
- Database executor interface.
- Validated execution helper that rejects invalid statements before they reach an executor.
- Migration step and migration plan models.
- Contiguous upgrade and explicit downgrade migration-plan validation; data-only
  migration statements (`INSERT`/`UPDATE`/`DELETE`) are accepted as no-op
  schema-state transitions, enabling backfill and corrective migrations such
  as the v5 `state_transitions` backfill.
- Initial schema deployed at version `1` in its final shape: 45 core
  tables covering every Matrix storage area from the project plan. There
  were no live databases at that time, so historical per-version migrations
  were collapsed into the single `initial_schema` step. Once live
  pre-production deployments existed, subsequent schema changes started
  receiving their own numbered migration files; schema version `2` adds the
  `sync_stream_watermark` table via `migrations/002_sync_stream_watermark.sql`,
  schema version `3` adds the `event_stream_watermark` table via
  `migrations/003_event_stream_watermark.sql`, schema version `4` adds the
  `state_transitions` table via `migrations/004_state_transitions.sql` so the
  server can populate `unsigned.replaces_state` for state events, and schema
  version `5` backfills `state_transitions` from `current_state` via
  `migrations/005_backfill_state_transitions.sql` so existing rooms do not lack
  transition history after the v4 upgrade, and schema version `6` adds the
  `account_threepids` table via `migrations/006_account_threepids.sql` so
  bound 3PID associations survive restarts rather than living only in the
  in-memory `vector<AccountThreePid>`, and schema version `7` adds the
  `client_secret` and `sid` TEXT columns to `account_threepids` via
  `migrations/007_account_threepids_columns.sql` so an IS-bound 3PID can be
  remotely unbound via IS unbind auth mode 2 (the stored pair is replayed in the
  unbind body; empty for local-only bindings), and schema version `8` adds the
  `pushers` table via `migrations/008_pushers.sql` so push notification
  pushers registered via `POST /_matrix/client/v3/pushers/set` survive
  restarts, and schema version `9` adds the `notifications` table via
  `migrations/009_notifications.sql` so `GET /_matrix/client/v3/notifications`
  history survives restarts (see "Notification history" below for the
  retention policy that keeps it bounded), and schema version `10` adds the
  `openid_tokens` table via `migrations/010_openid_tokens.sql` so tokens
  minted by `POST /_matrix/client/v3/user/{userId}/openid/request_token`
  survive restarts and can be redeemed by
  `GET /_matrix/federation/v1/openid/userinfo` (see "OpenID tokens" below),
  and schema version `11` ALTERs a `data_extra_json` column onto the
  existing `pushers` table via `migrations/011_pushers_data_extra.sql` (no
  new table) so custom members of a pusher's registration-time `data`
  dictionary — beyond the `url`/`format` keys already stored as dedicated
  columns — survive restarts and can be forwarded to the Push Gateway (see
  "Pushers" below), and schema version `12` adds the `login_tokens` table
  via `migrations/012_login_tokens.sql` so short-lived, single-use SSO login
  tokens minted by `homeserver::complete_sso_login` survive restarts and can
  be redeemed exactly once by `POST /_matrix/client/v3/login` with `type:
  m.login.token` (see "SSO login tokens" below).
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
- `database::revoke_tokens_for_user_except_device` (0.12.7) revokes every
  access and refresh token for a user *except* one named device, in a single
  `UPDATE ... WHERE user_id = $1 AND device_id <> $2` per token table — so a
  password change with `logout_devices: true` can revoke every other device
  without the caller's own tokens ever being revoked, and therefore without
  anything to restore afterward. This replaces the prior
  revoke-then-restore pair: `restore_tokens_for_device`, which re-activated a
  device's tokens by setting `revoked = false`, is **removed** from both the
  header and the implementation. That `UPDATE` could not distinguish a token
  it had revoked microseconds earlier from one revoked days earlier by an
  unrelated logout or admin action, so it resurrected all of them — handing
  back a token the very password change was meant to invalidate. **No
  function in the database layer may clear a `revoked` flag; revocation is a
  one-way transition.** A requirement of the shape "revoke some subset" must
  be expressed as a narrower revoke, never as a broad revoke followed by a
  restore. See [ADR-0052](adr/0052-revocation-of-credentials-is-one-way.md).
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
- `PersistentStore::server_signing_keys` has its own lock,
  `server_signing_keys_mutex` (0.12.13). The remote-key resolver stores and
  reads keys from federation relay threads and from backfill with the runtime
  mutex released, so after start-up hydration the vector is touched only
  through `store_server_signing_key`, `find_server_signing_key` and
  `snapshot_server_signing_keys` (a copy for callers that iterate). The lock is
  never held across the database write or a network call.
- Media bytes are not hydrated (ADR-0119). The SQLite and PostgreSQL loaders read
  `media_blobs` without its `bytes` column; `prepare_media_blob_read` (under the
  runtime mutex) and `read_media_blob` (without it) fetch one blob's bytes per
  request. A media upload writes its bytes in `commit_local_media_upload`; a
  deduplicated upload writes only `ref_count` (`update_media_blob_ref_count`).
  Remote media is admitted by `commit_remote_media_admission`, which in one
  transaction deletes the media and `remote_media` rows of the cache entries the
  admission displaces, sets those blobs' reference counts (clearing bytes at zero),
  and inserts the new media, blob and `remote_media` rows. `remote_media` carries
  `local_media_id` and `fetched_at_ms` since schema version 20.
- `room_aliases` carries `creator_user_id` since schema version 21 (CSAZ-12,
  ADR-0127): `store_room_alias` writes the creating user, empty for aliases
  created earlier, and `delete_room_alias` removes a mapping, in the database and
  in memory, for `DELETE /directory/room/{roomAlias}`.
- Binary payload columns are `BLOB` (#448): `media_blobs.bytes` holds raw media
  content and `server_signing_keys.secret_key` holds encrypted key material
  (`BLOB NOT NULL DEFAULT ''`, empty = no secret persisted). Both were folded
  into the version-1 initial schema per the pre-1.0 migration policy. SQLite
  column reads are length-based (`sqlite3_column_bytes`), so payloads
  containing NUL or invalid UTF-8 round-trip byte-exactly. `SchemaTableDefinition::columns_sql`
  is shared, backend-agnostic DDL text written in SQLite's dialect; PostgreSQL
  has no `BLOB` type, so `postgresql_store.cpp`'s `translate_ddl_types_for_postgresql()`
  rewrites `BLOB` to `BYTEA` (whole-word, so it cannot mangle an identifier)
  wherever a `SchemaTableDefinition` becomes DDL for that backend — both the
  bootstrap path and the migration-step path.
- Every SQLite connection pins `PRAGMA synchronous = FULL` and
  `PRAGMA journal_mode = DELETE` at open (#447), so an environment that
  installs global default pragmas cannot silently weaken durability.
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
- One fallback key per algorithm per device: `store_fallback_key` deletes the
  device's other fallback keys of the same algorithm and inserts the new one in a
  single transaction (spec v1.19, `POST /keys/upload`, `fallback_keys`).
- `key_signatures_for_target` reads key signatures through an in-memory index
  keyed by target user (`PersistentStore::key_signature_target_index`). The index
  is maintained by `store_key_signature`, rebuilt after SQLite and PostgreSQL
  hydration, copied with the store, and ignored (lookup scans) while its row count
  differs from `key_signatures`, so rows pushed directly never produce a missing
  result. Read signatures through this function, not by scanning the vector.
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
- `device_list_changes` holds at most one row per `(observer_user_id,
  subject_user_id)`. `database::record_device_list_change()` and
  `record_device_list_changes()` replace a pair's earlier row (a `DELETE` then an
  `INSERT` in one transaction) so it carries the newest stream position and the
  latest `change_type`; `/sync` reports only the latest change per subject, so
  nothing is lost, and a peer sending the same EDU repeatedly cannot grow the
  table. The batch form validates every change first, allocates one sync stream
  position for all of them and commits once. This needs no migration: the primary
  key stays `(stream_id, observer_user_id, subject_user_id)`. Rows written before
  this rule (duplicates per pair) are harmless, are collapsed by
  `sync::collect_device_list_delta()` on read, and are replaced the next time
  their pair changes.
- `event_stream_watermark` table stores the highest allocated timeline
  `stream_ordering` and is updated by `homeserver::allocate_stream_ordering()`
  (via `database::persist_event_stream_watermark()`) on every allocation. Some
  allocations — membership stream positions — are not backed by a persisted
  event row, so a counter rebuilt from `max(events.stream_ordering)` alone
  regresses across restarts, which puts clients' persisted sliding sync
  `pos`/`since` tokens ahead of the live stream and invalidates them all on
  every restart. Hydration takes the maximum of the persisted watermark and the
  highest event `stream_ordering`, then persists the merged floor so the row
  exists even on fresh upgrades.
- `state_transitions` table (schema version `4`, backfilled at schema version
  `5`) records the previous `event_id` for every state-event tuple replacement.
  It is populated by `database::store_state()` and the split
  `prepare_store_event_with_state()` / `apply_store_event_with_state()` helpers.
  The in-memory store keeps a hash index over `state_transitions` so that
  `client_event_with_id()` can inject `unsigned.replaces_state` into the client
  event format in O(1) rather than scanning the whole vector. For federated
  state events the previous event ID is derived by walking the event graph
  (`prev_events` and `auth_events`) to find the predecessor state event of the
  same `(room_id, event_type, state_key)` tuple, instead of assuming the local
  arrival-time current state was the predecessor.
- `account_threepids` table (schema version `6`, migration
  `migrations/006_account_threepids.sql`) records the 3PID bindings a user has
  added to their account, replacing the prior in-memory
  `vector<AccountThreePid>` which was lost on restart. Columns are `user_id`,
  `medium`, `address`, `country`, `id_server`, `added_at_ms`,
  `validated_at_ms`, and `bound`, with a unique key on `(medium, address)` so
  the same email/msisdn cannot be bound twice. The runtime migration path
  uses the compiled migration catalog in `src/database/migration.cpp`
  (upgrade step version `6` "account_threepids"; downgrade step version `5`
  "drop_account_threepids") rather than the on-disk `.sql` file, which
  remains the canonical schema definition.
- `account_threepids.client_secret` / `account_threepids.sid` columns
  (schema version `7`, migration
  `migrations/007_account_threepids_columns.sql`) store the
  `client_secret` + `sid` pair the IS issued for a binding, so a later remote
  unbind can replay them in the request body (IS unbind auth mode 2). Both
  columns are `TEXT NOT NULL DEFAULT ''`; they are populated only for IS-bound
  3PIDs and left empty for local-only bindings. The runtime migration path
  uses the compiled catalog in `src/database/migration.cpp` (upgrade step
  version `7` "account_threepids_columns"; downgrade step version `6`
  "drop_account_threepids_columns" — column drop precedes the v5 table drop
  on the downgrade walk).
- `PersistentThreePidBinding` struct (now carrying optional `client_secret`
  and `sid`) and the
  `store_account_threepid` / `find_account_threepid` /
  `delete_account_threepid` store functions
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  persist, look up, and remove bound 3PIDs. Implemented for both SQLite
  (`sqlite_store.cpp`) and PostgreSQL (`postgresql_store.cpp`); rows are
  hydrated into the in-memory store on backend open so existing bindings are
  visible immediately after restart.
- `pushers` table (schema version `8`, migration `migrations/008_pushers.sql`)
  records the push notification pushers a user has registered via
  `POST /_matrix/client/v3/pushers/set`. Columns are `user_id`, `app_id`,
  `pushkey`, `kind`, `app_display_name`, `device_display_name`,
  `profile_tag`, `lang`, `data_url`, `data_format` (the pusher's `data`
  dictionary's `url`/`format` keys, stored as plain columns rather than
  nested JSON), and — since schema version `11`, migration
  `migrations/011_pushers_data_extra.sql` — `data_extra_json` (a
  canonical-JSON-serialized object holding every OTHER member of the
  pusher's `data` dictionary at registration time; PR #479 review finding
  P1: the Push Gateway API's notify Device object is defined as "the data
  dictionary passed in at pusher creation minus the url key", so a custom
  member beyond `url`/`format` must survive a restart and reach the gateway,
  not just be discarded), with a primary key on `(user_id, app_id,
  pushkey)` — the spec's uniqueness rule: setting a pusher with the same
  `app_id` and `pushkey` for the same user replaces it in place. The
  runtime migration path uses the compiled catalog in
  `src/database/migration.cpp` (upgrade step version `8` "pushers", version
  `11` "pushers_data_extra"; downgrade step version `7` "drop_pushers",
  version `10` "drop_pushers_data_extra"); `schema::current_schema_
  version()` returns `11U`. The `PersistentPusher` struct and the
  `store_pusher` / `find_pusher` / `delete_pusher` / `list_pushers_for_user`
  store functions
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  persist, look up, list, and remove pushers, following the same pattern as
  `PersistentThreePidBinding` above; implemented for both SQLite and
  PostgreSQL, hydrated on backend open. `merovingian::push::PushGatewayClient`
  (`push_gateway_client.hpp`) forwards a device's `data_extra` members
  verbatim into the notify request body, and — since the PR #479 follow-up —
  `client_server.cpp`'s `parse_pusher_set_body()` captures every `data`
  member beyond `url`/`format` at registration time and `room_service.cpp`'s
  pusher-to-`PushGatewayDevice` conversion threads it through to a live
  delivery, so the gap noted above is closed end to end; see
  `docs/todos/capability-gaps.md`.
- `notifications` table (schema version `9`, migration
  `migrations/009_notifications.sql`) records the history
  `GET /_matrix/client/v3/notifications` serves. Columns are `user_id`,
  `room_id`, `event_id`, `stream_ordering` (the triggering event's global
  stream position — unique per row, since a recipient gets at most one
  notification per event, and doubles as this table's pagination key exactly
  like `events.stream_ordering` already does for `GET /messages`), `ts` (the
  event's `origin_server_ts`, milliseconds), `actions` (the canonical-JSON
  actions array reconstructed from the matched push rule's resolved outcome —
  `push_rules.hpp`'s `PushEvaluationResult` does not keep the rule's raw
  actions array, so `room_service.cpp`'s `push_notification_actions_json`
  rebuilds the conventional `["notify", {"set_tweak": ...}, ...]` shape),
  `profile_tag` (left empty: this recording happens once per `(user, event)`
  rather than once per pusher, so it cannot name one pusher's configured
  tag), and `highlight` (`"true"`/`"false"`, mirroring the matched rule's
  `set_tweak: highlight` action, so `?only=highlight` can filter without
  re-parsing `actions`), with a primary key on `(user_id, event_id)`. The
  runtime migration path uses the compiled catalog in
  `src/database/migration.cpp` (upgrade step version `9` "notifications";
  downgrade step version `8` "drop_notifications").
  The `PersistentNotification`
  struct and the `store_notification` / `list_notifications_for_user` store
  functions
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  persist and list rows, following the same pattern as `PersistentPusher`
  above; implemented for both SQLite and PostgreSQL, hydrated on backend
  open. `room_service.cpp`'s `build_pending_push_deliveries()` calls
  `store_notification` for every local recipient whose push rule evaluation
  resolves `notify: true` — **unconditionally**, regardless of
  `server.push.enabled` or whether that recipient has a registered pusher:
  `GET /notifications` returns events the user "has been, or would have
  been, notified about" (spec), so a user with push turned off must still
  see their history. Only the Push Gateway delivery half of that function
  (building a `PendingPushDelivery` and dispatching it) stays gated on
  `push.enabled` + a registered pusher. The `read` field the endpoint reports
  is *not* stored on the row — it is computed at request time from
  `sync::read_receipt_ordering()` against the caller's current `m.read`/
  `m.read.private` receipt in that room, so it always reflects the latest
  receipt without a write-side update on every receipt change.
  **Retention:** `store_notification` prunes the oldest rows for that
  `user_id` beyond `server.client_api.max_notifications_retained_per_user`
  (default 1,000, valid range 1..100,000), after every insert. The same policy
  applies to the in-memory mirror and SQLite/PostgreSQL persistence; rows with
  the oldest stream ordering are removed first. It is independent of
  `server.push.max_in_flight_deliveries`, which bounds background tasks rather
  than persisted rows. Recording still occurs when push delivery is disabled.
  Increasing retention preserves more future history but cannot restore rows
  already pruned under an earlier policy. Changing the policy requires restart.
- `openid_tokens` table (schema version `10`, migration
  `migrations/010_openid_tokens.sql`) stores the short-lived tokens minted by
  `POST /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19
  CS API §OpenID) and redeemed by `GET /_matrix/federation/v1/openid/userinfo`
  (SS API §OpenID). Columns are `user_id`, `token_hash` (primary key), and
  `expires_at` (epoch milliseconds, encoded the same way as
  `access_tokens.expires_at` / `refresh_tokens.expires_at` via
  `expires_at_text`/`parse_expires_at`). Unlike an access token's expiry,
  `expires_at` is never optional here — every OpenID token has a finite
  lifetime. The runtime migration path uses the compiled catalog in
  `src/database/migration.cpp` (upgrade step version `10` "openid_tokens";
  downgrade step version `9` "drop_openid_tokens"); `schema::current_schema_
  version()` returns `10U`. This is a **separate table from `access_tokens`**,
  by design — see `docs/auth-identity.md` ("OpenID tokens") and
  `docs/threat-model.md` for why that separation is the entire security
  property this feature depends on. The `PersistentOpenidToken` struct and
  the `store_openid_token` store function
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  persist rows, following the same hashed-token pattern as
  `PersistentAccessToken`; implemented for both SQLite and PostgreSQL,
  hydrated on backend open. `homeserver::request_openid_token` (`src/
  homeserver/auth_service.cpp`) mints and hashes the token — reusing the same
  keyed-hash machinery (`issue_token_hash`, preferring the master-key-derived
  v4 HMAC) access tokens use, since the hash *algorithm* is not the security
  boundary here — and `homeserver::federation_openid_userinfo` is the only
  function that ever reads this table back; the ordinary client-server auth
  gate (`authenticated_user`) never consults it, and `federation_openid_
  userinfo` never consults `access_tokens`/`sessions`. **Retention:**
  `store_openid_token` sweeps every already-expired row (across all users, not
  just the one being inserted) on each insert — appropriate because an OpenID
  token's natural bound is its own short expiry (one hour; see
  `docs/auth-identity.md`) rather than a per-user row count, unlike
  `notifications`' count-based cap above.
- `login_tokens` table (schema version `12`, migration
  `migrations/012_login_tokens.sql`) stores the short-lived, single-use
  tokens minted by `homeserver::complete_sso_login` when an SSO
  authentication completes (Matrix v1.19 CS API §"Client login via SSO")
  and redeemed exactly once by `POST /_matrix/client/v3/login` with `type:
  m.login.token` (`homeserver::redeem_login_token`). Columns are `user_id`,
  `token_hash` (primary key), `expires_at` (epoch milliseconds, same
  encoding as `openid_tokens.expires_at`), and `used` (`TEXT NOT NULL
  DEFAULT 'false'`, following the `revoked`-column boolean-as-text
  convention `access_tokens`/`refresh_tokens` already use). The runtime
  migration path uses the compiled catalog in `src/database/migration.cpp`
  (upgrade step version `12` "login_tokens"; downgrade step version `11`
  "drop_login_tokens"); `schema::current_schema_version()` returns `12U`.
  This is a **separate table from `access_tokens`**, for the same
  token-confusion reason `openid_tokens` is — see `docs/auth-identity.md`
  ("SSO login") and `docs/threat-model.md` ("Open redirect and login-token
  exfiltration via SSO redirectUrl"). `database::store_login_token` persists
  a row (reusing `issue_token_hash`, the same keyed-hash machinery access
  tokens use) and mirrors the openid-token retention strategy: every insert
  sweeps every already-expired-or-used row, not just the one just inserted,
  since a login token's natural bound is its own ~30s expiry or single use
  rather than a row count. `database::consume_login_token` is the only
  function that ever reads this table back and is the sole redemption path:
  it finds an unused, unexpired row matching one of the candidate hashes
  (constant-time compared via `crypto::constant_time_equal`), marks it used
  in the backend *before* returning the owning `user_id` so a persistence
  failure can never leave a token silently redeemable twice from memory
  alone, and returns `nullopt` on any miss (unknown, expired, or
  already-used token are indistinguishable to the caller). Implemented for
  both SQLite and PostgreSQL, hydrated on backend open.
- `appservice_txn_cursor` table (schema version `13`, migration
  `migrations/013_appservice_txn_cursor.sql`) persists the outbound
  `PUT /_matrix/app/v1/transactions/{txnId}` delivery cursor for each
  registered Application Service API (Matrix v1.19) appservice, keyed on
  `appservice_id` (one row per appservice). Columns: `next_txn_id` (the
  next fresh transaction id to allocate — monotonic, never reused),
  `delivered_stream_ordering` (high-water mark: every event up to and
  including this position has been acknowledged), `pending_txn_id` and
  `pending_stream_ordering` (the currently in-flight, unacknowledged batch,
  if any — `pending_txn_id == 0` means none). Every field is stored as
  `TEXT`, matching this table's `pushers`/`notifications`/`openid_tokens`
  neighbours, and parsed back to `std::uint64_t` at hydration. The
  `PersistentAppserviceTxnCursor` struct and the
  `find_appservice_txn_cursor`/`store_appservice_txn_cursor` store functions
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  are implemented for both SQLite and PostgreSQL, hydrated on backend open.
  Delivery itself (`room_service.cpp`'s `dispatch_appservice_delivery`,
  called from `send_event()`, `dispatch_membership_push_notification()`, and
  the federation `deliver_federation_push_notifications()` path) replays
  forward through the existing `events` table by `stream_ordering` rather
  than maintaining a separate durable outbox — this row is the *entire*
  persisted delivery state. A retry of an in-flight batch reuses the exact
  same `pending_txn_id` and re-derives the identical single event from
  `events`, never growing it, per the spec's "Homeservers MUST NOT alter
  ... events they were going to send within that transaction ID on
  retries." Delivery is synchronous (on the request path that produced the
  triggering event), not a background/async dispatch like push notification
  delivery — see `dispatch_appservice_delivery`'s doc comment for why, and
  `docs/todos/capability-gaps.md` for the documented follow-up.
- `users.deactivated` column (schema version `14`, migration
  `migrations/014_user_deactivation.sql`) is a `TEXT NOT NULL DEFAULT
  'false'` column added to the existing `users` table (no new table), set by
  `POST /_matrix/client/v3/account/deactivate` (see `docs/auth-identity.md`
  "Account deactivation"). It is deliberately distinct from the existing
  reversible `locked`/`suspended` columns: a deactivated account can never
  log in again, and its row is retained (not deleted) so the localpart is
  never reissued to a new registration. The runtime migration path uses the
  compiled catalog in `src/database/migration.cpp` (upgrade step version
  `14` "user_deactivation", an `ALTER TABLE users ADD COLUMN` statement;
  downgrade step version `13` "drop_user_deactivation"); `schema::current_
  schema_version()` returns `14U`. `set_user_deactivated`
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  updates the column and mirrors the change into the in-memory
  `PersistentUser`, following the same pattern as `set_user_account_state`
  above; implemented for both SQLite and PostgreSQL, hydrated on backend
  open. Adding a sixth column to `users` also exposed a latent risk in
  `store_user`'s insert statement: it previously used a bare `INSERT INTO
  users VALUES (...)`, which binds parameters by position and would have
  silently mismatched had the column order or count changed elsewhere.
  `store_user` now names every column explicitly (`INSERT INTO users
  (user_id, password_hash, locked, suspended, admin, deactivated) VALUES
  (...)`), so a future schema change to `users` fails loudly (wrong
  parameter count) rather than silently binding a value to the wrong column.
- **Phase A of spec-conformant PDU ingestion (schema version `15`, migration
  `migrations/015_event_graph_state.sql`, ADR-0064): delta state groups,
  forward extremities, and event status.** This is storage plumbing only —
  it does not change how PDUs are ingested, how local events pick
  `prev_events`, or what clients see; that is later phases. Adds:
  - `events.status` — `TEXT NOT NULL DEFAULT 'accepted'`, one of
    `'accepted' | 'soft_failed' | 'rejected' | 'outlier'` (spec: "Checks
    performed on receipt of a PDU"). `set_event_status`/`find_event_status`
    get/set it, validating the value and mirroring the change into the
    in-memory `PersistentEvent::status` field (appended as that struct's
    last member, defaulting to `"accepted"`, so no existing brace-init call
    site needed to change).
  - The pre-existing `state_groups` table (created at v1 but never
    populated or read by any code path before this — confirmed vestigial by
    grep) gains `parent_state_group_id` (`TEXT NOT NULL DEFAULT ''`) and
    `delta_depth` (`TEXT NOT NULL DEFAULT '0'`), turning it into the root of
    a delta chain. Like every other nullable-in-spirit column in this
    schema (e.g. `state_transitions.previous_event_id`), the empty string is
    the "no parent, this is a snapshot" sentinel rather than a SQL `NULL` —
    `PreparedStatement`/`BoundValue` has no NULL parameter representation,
    and this keeps the convention consistent with the rest of the schema.
    In C++, `PersistentStateGroup::parent_state_group_id` is
    `std::optional<std::string>` (`nullopt` ⇔ the empty-string sentinel).
    `state_group_edges` (also created at v1, also vestigial) is
    deliberately left alone — see "Federation worker least-privilege role"
    below for whether it should eventually be dropped.
  - `state_group_state (state_group_id, event_type, state_key, event_id)` —
    one group's own rows: the full state for a snapshot group
    (`parent_state_group_id` empty), or just the changed entries for a
    delta group.
  - `event_state_groups (event_id PRIMARY KEY, state_group_id)` — maps an
    event to the group holding the room's state immediately after it.
  - `forward_extremities (room_id, event_id)` — a room's current DAG
    leaves.
  - **Index:** `event_edges_prev_event_id ON event_edges (prev_event_id)` —
    the project's first index. `event_edges`' primary key is `(event_id,
    prev_event_id)`, which cannot serve a lookup keyed on `prev_event_id`
    alone; the migration's own `seed_forward_extremities` step probes
    exactly that (is this event anybody's `prev_event_id`?) once per event,
    and phase B's future ingest-time "children of this event" lookup needs
    the same shape. Without the index both are a full table scan per probe
    — O(events × edges) for the seed step alone. The index is created
    before the seed statements run, so seeding itself uses it; confirmed
    by `EXPLAIN QUERY PLAN` in
    `tests/integration/test_state_groups_flow.cpp`'s "event_edges has a
    usable index for prev_event_id lookups" scenario. `state_groups` gets
    no matching `room_id` index: every store function that reads it
    (`find_state_group`, `read_state_group_full_state`,
    `create_or_reuse_state_group`'s parent lookup) looks up by
    `state_group_id`, its primary key — nothing queries it by `room_id`.

  Store API ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp)):
  `create_or_reuse_state_group(store, room_id, new_state_group_id,
  parent_state_group_id, full_state)` builds the group that will hold
  `full_state` — reusing `parent_state_group_id` unchanged when `full_state`
  is exactly the parent's own state (read via `read_state_group_full_state`,
  never re-derived by re-diffing the raw rows a second way), writing a full
  snapshot when there is no parent, the parent's `delta_depth + 1` would
  exceed `events::max_state_group_delta_depth` (100), or `full_state` is
  missing a key the parent has (deltas never encode deletions — state
  resolution never drops a key present in any fork, so this should not
  happen, but a missing parent key is handled safely rather than assumed
  impossible), and otherwise writing only the changed entries as a delta.
  Fails closed (returns `nullopt`) if the named parent does not resolve.
  `read_state_group_full_state(store, state_group_id)` walks parent links
  back to the snapshot and applies every delta on the chain, newest first;
  bounded to `max_state_group_delta_depth + 1` hops and cycle-detected — a
  missing group, a cycle, or an over-long chain returns `nullopt`, never a
  partial map. `find_state_group` returns a group's own row (not its
  resulting state). `update_forward_extremities(store, room_id, event_id,
  prev_event_ids, accepted)` removes `prev_event_ids` from and adds
  `event_id` to the room's extremity set when `accepted` is true, and is a
  no-op when false (soft-failed/rejected events never become extremities
  and never remove one); `find_forward_extremities` reads the current set.
  All four are implemented for SQLite, PostgreSQL, and the in-memory store's
  write-through path (the `PersistentStoreBackend::memory` backend commits
  trivially, so unit tests exercise the in-memory bookkeeping directly —
  see `tests/unit/test_state_groups.cpp`).

  The migration seeds every pre-existing room in portable SQL (`INSERT ...
  SELECT ... WHERE NOT EXISTS (...)`, idempotency-guarded so re-running the
  migration chain is a no-op): one snapshot state group per room
  (deterministic id `'seed:' || room_id`) built from its `current_state`,
  attached via `event_state_groups` to the room's current forward
  extremities (the events `event_edges` names as nobody's `prev_event_id`,
  seeded into `forward_extremities`). Events older than a room's
  extremities get no state group at seed time — a later phase treats them
  as outliers if it ever reaches them. Integration coverage
  (`tests/integration/test_state_groups_flow.cpp`) brings a real SQLite
  database to v14 by replaying the compiled migration catalog by hand
  (every v1–v14 statement happens to be parameter-free, so plain
  `sqlite3_exec` suffices), seeds a room at that shape, then opens the
  store through the public API so migration 015 runs for real and asserts
  the seeded snapshot/extremities/mappings/statuses; a PostgreSQL-gated
  scenario (skips without `MEROVINGIAN_TEST_POSTGRESQL_URI`, like every
  other live-database scenario in this suite) checks the new tables exist
  after bootstrap.
- **Phase B1 of spec-conformant PDU ingestion (0.12.13, ADR-0064): the phase
  A tables are now written and read on the live ingest path**, not just
  seeded for pre-existing rooms. New module
  [`merovingian::homeserver::state_bookkeeping`](../include/merovingian/homeserver/state_bookkeeping.hpp)
  (`src/homeserver/state_bookkeeping.cpp`):
  - `compute_state_before(store, room_id, policy, prev_event_ids)` — the
    state immediately before an event: a single `prev_event`'s own
    after-state directly (`find_event_state_group` +
    `read_state_group_full_state`, no resolution needed); several
    `prev_events` resolved via `events::resolve_state_v2` over their
    after-states. Fails closed (`StateBeforeResult::ok = false`) if any
    `prev_event` has no recorded state group, or resolution itself does
    (ADR-0063's walk cap) — never silently substitutes current state.
  - `compute_state_after(state_before, event_id, event_type, state_key)` —
    `state_before` plus the event itself when it is a state event.
  - `record_event_state(store, room_id, event_id, prev_event_ids,
    state_after)` — creates or reuses the after-state group (chained off
    `prev_event_ids.front()`'s own group as the delta parent, so unchanged
    state reuses it per `create_or_reuse_state_group`'s own dedup), maps
    `event_id` to it, and updates forward extremities.
  - `recompute_current_state(store, room_id, policy)` — current state as
    the resolution over the room's forward extremities (one extremity: its
    after-state directly; several: `resolve_state_v2`), diffed against the
    cached `current_state` and written only where changed, through
    `database::store_state` — the same call every other state write already
    used, so `state_transitions` (`unsigned.replaces_state`) and the
    existing sync wake-up path (`SyncNotifier::publish`, called by the
    ingest caller on an accepted result) stay correct with no separate
    "state diff" plumbing. `current_state` is a cache of this result, never
    an independent write target, from this path onward.

  Wired into `ingest_pdu_event` (`src/homeserver/local_http_router.cpp`):
  state-before is computed before the event is persisted (a missing
  prev-state fails the PDU closed with the new
  `federation::PduIngestionStatus::missing_prev_state` — not a rejection;
  the transaction it arrived in still returns 200 per spec, since a
  delayed-but-legitimate PDU is indistinguishable from one whose history we
  have not fetched yet); the after-state group, forward-extremity update,
  and current-state recomputation happen after the event is durably stored,
  logged-but-non-fatal on failure (the same trade-off the pre-existing
  membership-persistence step in the same function already makes for the
  same reason: the raw event is already committed, so failing the PDU here
  would only cause pointless retries).

  **Phase B1 completion (same 0.12.13 branch, follow-up commits):** every
  local and inbound-accepted event path now goes through this bookkeeping,
  not just `ingest_pdu_event`.
  - `homeserver::store_local_event` (`state_bookkeeping.hpp`/`.cpp`) is the
    choke point every locally created event must go through — runs the same
    compute-state-before / store / record-after-state / recompute sequence
    as `ingest_pdu_event`, but every failure is a hard failure (the request
    fails), since a local event has not yet been told "success" to anyone.
    `homeserver::forward_extremities_for_new_event` gives local events their
    `prev_events` from the room's real forward extremities (capped at the
    spec's 20 per event, `events::max_prev_events_per_event`, highest depth
    kept) instead of the previous, DAG-unaware "last event pushed into
    `store.events`" heuristic. `persist_composed_event` (`room_service.cpp`
    — used by `create_room`'s initial-state chain, invite/join composition,
    and every ordinary send/state-send/redaction) calls it instead of
    `database::store_event_with_state` directly.
  - `local_http_router.cpp`'s `membership_acceptor` (a remote user's
    `send_join`/`send_leave`/`send_knock` into a room we are resident in —
    the same trust boundary as `ingest_pdu_event`) gets the identical
    state-before check and after-state/current-state bookkeeping.
    `invite_handler`'s invite-event store gets explicit `status =
    "outlier"` (it is never part of this server's own timeline).
  - The federated-join flow (`join_room`/`perform_federated_join`,
    `room_service.cpp`) now seeds a snapshot state group from the
    `send_join` response's state (stored as `status = "outlier"` events by
    `ingest_send_join_state`, which returns the full state map alongside
    the joined-members list), gives the join event an after-state group
    chained off that snapshot (`homeserver::record_event_state_with_parent`,
    `record_event_state` generalised to an explicit parent group), and
    makes it the room's sole forward extremity — so the first inbound PDU
    after a join no longer hits `missing_prev_state`. Since FED-1
    (ADR-0083) only entries whose room is the joined room are stored, and
    `auth_chain` events are stored as outliers with no `current_state` row;
    `repair_missing_state_entries` (start-up) likewise only promotes
    `accepted` events, never an outlier or a rejected one.
  - A source-tree guard test (`tests/unit/test_store_event_choke_point.cpp`)
    fails the build if `database::store_event_with_state(` appears anywhere
    in `src/` outside a reviewed, counted allowlist.
  - `PduStateConflictContext` / `state_conflict_resolver` (the older,
    never-production-reached conflict-resolution plumbing this phase was
    meant to replace) are still left in place unchanged and unused —
    phase B2 removes them.

  A real bug was found and fixed along the way: `database::store_state`'s
  `state_transitions` insert had no `ON CONFLICT` handling, but its primary
  key is `(room_id, event_type, state_key, event_id)` — state resolution
  making an event current again after it was already superseded once (the
  spec's "reverts to an older event" case) re-inserts that same key, which
  both backends reject as a duplicate row; the write is now an upsert
  (`ON CONFLICT (...) DO UPDATE SET previous_event_id = excluded.previous_event_id`),
  with the in-memory `state_transition_index` mirror updated to match.

  Tests: `tests/unit/test_state_bookkeeping.cpp`,
  `tests/unit/test_pdu_ingestion_state_groups.cpp`,
  `tests/unit/test_local_event_state_bookkeeping.cpp`, and
  `tests/unit/test_store_event_choke_point.cpp` (all
  `[pdu_ingestion][state_groups]`) cover the module directly, end-to-end
  through `ingest_pdu_event`, end-to-end through local send/create paths,
  and the source-tree guard, respectively;
  `tests/integration/test_join_room_flow.cpp` covers the federated-join
  seeding end to end; `tests/unit/test_sync_handler.cpp` covers a
  resolution-driven reactivation reaching an incremental `/sync` client.
- **Token rotation lineage (schema version `17`, migration
  `migrations/017_token_rotation_lineage.sql`, ADR-0074).** `refresh_tokens`
  gains `predecessor_hash` and `access_tokens` gains
  `predecessor_refresh_hash` (both `TEXT NOT NULL DEFAULT ''`, via `ALTER
  TABLE`). A token pair minted by `POST /refresh` records the hash of the
  refresh token it replaced, which stays valid until the pair is first used
  (see `docs/auth-identity.md`). Both backends store and hydrate the columns;
  `database::revoke_refresh_tokens_with_predecessor` supersedes an unused
  pair when a refresh is retried. The downgrade step drops both columns.
  Hydration (`homeserver::hydrate_local_database`) also copies each access
  token's `expires_at` into its session; before 0.12.13 it did not, so
  expiry was not enforced after a restart.
- **M05 authenticated-media storage (schema version `16`, migration
  `migrations/016_media_legacy_endpoint_visibility.sql`,
  [ADR-0068](adr/0068-random-media-ids-and-legacy-endpoint-freeze.md)).**
  The `media` table gains a `legacy_endpoint_visible` column (`TEXT NOT NULL
  DEFAULT 'true'`) via an `ALTER TABLE` migration, keeping the v1 `media`
  table definition historically intact exactly like v14's `users.deactivated`
  addition. New local uploads are stored with `legacy_endpoint_visible = false`
  (see `docs/media-repository.md`); the unauthenticated
  `/_matrix/media/v3/download` and `/thumbnail` routes treat a `false` value
  as a 404, while authenticated `/_matrix/client/v1/media/...` routes ignore it
  and serve the media. Existing rows default to `'true'`, so pre-upgrade
  unauthenticated links keep working. The runtime migration path uses the
  compiled catalog in `src/database/migration.cpp` (upgrade step version
  `16` "media_legacy_endpoint_visibility"; downgrade step version `15`
  "drop_media_legacy_endpoint_visibility"); `schema::current_schema_version()`
  returns `16U`. Adding a column to the `media` table does not affect the
  federation worker table classification: `media` remains in
  `worker_never_reads_tables`, so the worker allowlist needs no change.
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
- Committed statements are not retained (AUTH-11). `commit_persistent_transaction`
  used to append every committed `PreparedStatement`, bound parameters included,
  to `PersistentStore::prepared_statements`, which nothing trimmed. The store now
  keeps nothing unless a test calls `enable_statement_capture(store, capacity)`;
  the capture is `PersistentStore::captured_statements`, holds at most
  `capacity` statements (clamped to `max_statement_capture_capacity`, 65 536),
  drops the oldest first, and is empty and disabled by default.
  `sensitive_values_are_redacted` reads that capture and returns false when capture
  is disabled instead of passing on an empty buffer. Production code never enables
  capture: password and token hashes must not outlive the commit in process memory.
- `PersistentStore::audit_log` is a bounded window (AUTH-1): the newest
  `max_in_memory_audit_events` (1 024) rows, oldest dropped first, with
  `audit_log_evicted` counting what left. The table is the complete record.
  Append through `append_audit_event`; hydrate through `remember_audit_event`.
  Hydration keeps the newest rows in insertion order on both backends (PostgreSQL
  orders by `ctid`, the only ordering the column-less `audit_log` offers).
  `load_audit_events_by_type_prefix(store, prefix, limit)` reads older rows straight
  from the table (newest first, `limit` clamped to `max_audit_query_rows`, prefix
  bound and matched literally); in-memory stores answer from the window.
  `append_audit_event` cuts `actor`, `target` and `reason` to 255 bytes on a UTF-8
  boundary. See `docs/observability-audit.md`, "Audit volume bounds".
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
- **Bootstrap table-identifier validation (issue #442):** PostgreSQL's
  `create_table_if_missing_sql` previously concatenated `table.name` directly
  into `CREATE TABLE IF NOT EXISTS <name> (...)` DDL with no validation or
  quoting, unlike the SQLite path. It now mirrors `sqlite_store.cpp` exactly:
  `schema_table_is_core()` gates the name to the compiled core-table set, and
  `quote_sqlite_identifier()` (generic ANSI double-quote identifier quoting,
  despite the name — valid for PostgreSQL too) wraps it. Current callers only
  ever pass hardcoded core table names, so this is defense-in-depth against a
  future caller passing a non-core or attacker-influenced name.

- Client transaction-idempotency dedup via the version-1 `client_txn_ids` table.
  Keyed on `(user_id, room_id, event_type, txn_id)`; `room_id` is empty string
  for to-device sends. `event_id` stores the assigned event ID for room sends and
  is empty for to-device entries. Both SQLite and PostgreSQL hydrate rows on
  startup. Handlers check the table before processing and store the result after
  a successful send, allowing clients to safely retry `PUT /rooms/{roomId}/send`
  and `PUT /sendToDevice` requests.
- `database::reload_room(store, room_id)` re-reads a single room's rows (room,
  membership, invites, events, state, and the event-relation tables scoped to
  that room's events) from the backing database and replaces this store's
  in-memory copy of that room. Implemented for both SQLite and PostgreSQL with
  parameterised, room_id-scoped queries (never a full-table re-read). A no-op
  (returns `true`) for the `memory` backend. Used by the federation worker to
  refresh its otherwise-stale `PersistentStore` snapshot — see
  [architecture.md, "Federation worker room staleness"](architecture.md#federation-worker-consistency-model).
- `database::reconstruct_event_relations(store)` re-derives every
  `PersistentEvent::prev_event_ids`/`auth_event_ids`/`signatures` from the flat
  `event_edges`/`event_auth`/`event_signatures` tables. Those fields are only
  populated directly when an event is stored fresh within a process's own
  lifetime (`store_event_with_state`); hydrating a store from disk previously
  left them silently empty. Called at the end of both
  `open_sqlite_persistent_store`/`open_postgresql_persistent_store` and as
  part of `reload_room`'s snapshot merge. Idempotent.
- `database::store_event_with_state()` is split into
  `prepare_store_event_with_state()`, `commit_persistent_transaction()`, and
  `apply_store_event_with_state()`. The `PreparedStateUpdate` struct holds the
  event, optional state event, and the prepared statements. `prepare` validates
  in-memory pre-conditions (room existence, duplicate event id) and builds the
  statements. `commit` executes them on the backend without holding any room
  lock, so different rooms can commit concurrently. `apply` mirrors the committed
  rows into the in-memory vectors with an idempotent duplicate guard. Used by
  the per-room inbound PDU path so the global runtime lock is released before
  the database commit. The combined helper remains for callers that do not need
  the split.

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
  Token revocations (logout, logout-all, refresh rotation and reuse, device
  deletion, password change) are checked against the store after the write, and
  a revocation that did not persist answers 500 (DB-5, ADR-0116).
- A media upload is answered with an `mxc://` URI only after its media row and
  blob are committed together (`commit_local_media_upload`, one transaction). A
  failed commit answers 500 and `media::rollback_local_media_upload` removes the
  record and releases the blob reference in memory, so a restart cannot lose
  media a client was told was stored (DB-5). Media moderation commits flags,
  blob references and its audit row together (`commit_local_media_moderation`).
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
- No store function may clear a `revoked` flag once set — revocation is a
  one-way transition, enforced by the store's API surface rather than by
  caller discipline (see `revoke_tokens_for_user_except_device` above and
  [ADR-0052](adr/0052-revocation-of-credentials-is-one-way.md)).
- Binary (`BLOB`) columns round-trip byte-exactly on both backends. The columns
  are `media_blobs.bytes` and `server_signing_keys.secret_key` — every `BLOB`
  in `migrations/*.sql` and `schema.cpp`; a new one must follow this
  mechanism. `BoundValue` carries a `binary` flag, and a write must set it for
  every `BLOB` parameter. SQLite binds every parameter by explicit length and
  reads columns by `sqlite3_column_bytes`, so it ignores the flag and is
  unchanged. On PostgreSQL, `execute_prepared_statement` binds a `binary`
  parameter in libpq's binary wire format (`paramFormats` = 1, explicit
  `paramLengths`, declared type `bytea`), so arbitrary bytes — NULs, invalid
  UTF-8, backslashes — arrive exactly and nothing is escaped or truncated.
  The read side is one generic rule rather than a per-table special case:
  `load_result_rows` asks libpq for each result column's type (`PQftype`) and
  decodes every `bytea` column from PostgreSQL's `\x` hex text form back to raw
  bytes, so any query that selects a `BLOB` column gets bytes, not hex. Each
  connection pins `SET bytea_output = 'hex'` at open so a role or database
  default of `escape` cannot change that form; a `bytea` value that is not
  valid hex fails the query rather than returning empty or garbled bytes,
  because an empty `secret_key` reads as "no signing key" and would make the
  server mint a new identity. Until DB-1 was fixed only `media_blobs.bytes` was
  decoded, so the signing secret came back as its own hex text after a restart
  and the server could not load its signing key (0.12.14 audit). Existing
  rows hold the raw bytes intact, so no data migration was needed.
- Identity-server unbind credentials (`account_threepids.client_secret` and
  `.sid`) are bound as sensitive values, so they never reach a query trace or
  diagnostic log. They remain plaintext at rest; that is the documented residual
  risk in `docs/threat-model.md` §IS-delegated bind/unbind/requestToken.
- Migration plans are serialised across processes. Each step commits in its own
  transaction, so the window that needs protecting is *between* the
  transactions: PostgreSQL takes a `pg_advisory_lock` for the whole plan under
  an RAII lease (a crashed migrator's session-scoped lock disappears with its
  connection, so recovery needs no operator action), and SQLite re-reads the
  `schema_migrations` ledger inside each step's `BEGIN IMMEDIATE` and skips a
  step the winner of a race already applied. These are deliberately *not* one
  shared mechanism — see
  [ADR-0059](adr/0059-serialise-migrations-per-backend-not-per-abstraction.md).

## Deliberately not included

These remain deferred:

- Hydration of the federation queue tables (`federation_destinations`,
  `federation_transactions`) and of `push_rules`, on both backends. Policy
  rules and media blob metadata are hydrated on both backends (see above).

## Next starting points

1. Extend transaction helpers across federation queues, policy actions, and
   media metadata once those rows are runtime-wired.
2. Persist push rules, federation queues, and media blob metadata.
3. **Wire PostgreSQL migration/runtime role separation into the live
   connection path (production-milestone.md release blocker).** Today the
   role-enforcement mechanism (`set_postgresql_role`/`reset_postgresql_role`,
   `docs/database-persistence.md` above) and its CI proof
   (`postgres-integration.yml`) are real and passing, and
   `packaging/postgresql/provision-roles.sql` provisions the two roles for an
   operator — but nothing in the live startup path actually calls
   `set_postgresql_role()`. `merovingian-db-migrate` (`src/db_migrate.cpp`)
   never opens a database connection at all; it only prints an offline
   migration *plan*. Schema migrations are applied automatically by
   `bootstrap_local_database()`/`migration.hpp` on every server startup.
   **Partly closed in 0.12.3**: when `database.runtime_role` is configured,
   every PostgreSQL connection assumes it after opening — not just the
   bootstrap one, since connections are created per operation — and an
   unassumable role refuses the open rather than serving with the login
   role's wider privileges.

   **Closed for the server in 0.12.5** (audit finding 18). Migrations had
   continued to run as the login role because `ALTER TABLE` is permitted only
   to an object's owner and the migration role owned nothing — so the
   separation did not cover the one operation that actually needs DDL. The
   answer is for the migration role to own the schema:

   - `provision-roles.sql` creates objects under `:migration_role`, and ends
     with a scoped transfer of the `public` tables and sequences `:login_role`
     still owns — the one step an existing database needs before upgrading.
     The `postgres-integration` CI job runs the same statements, so the
     operator sequence is exercised. It is deliberately not `REASSIGN OWNED`,
     which operates on everything the role owns including pinned system
     objects, and so fails when the login role is the cluster bootstrap
     superuser.
   - `open_postgresql_persistent_store()` takes `database.migration_role`,
     `SET ROLE`s to it before applying pending migrations, and resets the
     session before assuming the runtime role.
   - An unassumable migration role refuses the open rather than falling back
     to the login role. Only a *pending* migration reaches the role switch, so
     a misconfigured `migration_role` breaks an upgrade rather than every
     routine restart; leaving it unset keeps single-role deployments working.

   Still open: `merovingian-db-migrate` becoming a real tool that connects
   rather than printing an offline plan. The startup path is covered by the
   role-separation and migration-role scenarios in
   `test_postgresql_persistence_flow.cpp`, which drive
   `open_postgresql_persistent_store` itself rather than the primitive in
   isolation — note they require a live PostgreSQL URI and role environment
   variables, so they run only in `postgres-integration`. See
   `packaging/postgresql/provision-roles.sql` for the stricter alternative
   (never grant the login role membership of the migration role; run
   migrations out-of-band and leave `database.migration_role` unset).

## Federation worker least-privilege role (ADR-0062 part 2)

The out-of-process federation worker (`merovingian-fed-worker`,
`src/federation_worker/`) is the process most exposed to hostile input (see
`src/federation_worker/AGENTS.md`). Before 0.12.13 finding N1 part 2, it
opened the database with the *same* PostgreSQL login as main, so a
compromised worker could `SELECT` `server_signing_keys.secret_key` (still
ciphertext, but exactly what decrypts it once the operator master key is
recovered by an unrelated bug — see ADR-0062 part 1) and every other
credential-bearing table, even though no worker code path ever reads them.

Two independent mechanisms close this, together:

1. **A separate login, not `SET ROLE`.** `SET ROLE`-based separation was
   rejected for this boundary specifically: a session holding the *login*
   role that granted a restricted role can always `RESET ROLE` back to it,
   so a compromised worker holding the original login credential gains
   nothing from a restricted role it can trivially undo. Only a distinct
   login credential the worker process never holds in the first place is a
   real boundary — see ADR-0062's "Options considered and rejected". The new
   config key `federation.worker.database_uri_file` names a secret file
   holding this login's connection URI. Main reads and validates it exactly
   like `database.uri_file` (owner-only, regular file, TOCTOU-safe —
   `validate_existing_secret_file_metadata` in `src/main.cpp`) and hands the
   bytes to each worker shard over a third inherited pipe fd
   (`homeserver::kWorkerDbUriFd`, `--db-uri-fd` on the child's argv) — the
   worker itself never opens this file. `federation_worker::
   apply_worker_database_uri` then sets `database.worker_conninfo_override`
   on the worker's own in-memory `Config` copy and clears `uri_file`,
   `runtime_role`, and `migration_role`: the separate role connects
   directly with its own grants, never attempting a `SET ROLE` against roles
   it was never made a member of. `packaging/postgresql/
   provision-federation-worker-role.sql` provisions the role; see that
   file's header comment for the full GRANT SQL and the reasoning behind
   each statement. It grants `SELECT` only — never `INSERT`/`UPDATE`/
   `DELETE` — since the worker's own `PersistentStore` is a read-only
   snapshot for room-scoped federation reads and every write it needs is
   relayed to main over IPC (`src/federation_worker/AGENTS.md` rule 3; the
   one exception found during review is `state_conflict_resolver`, covered
   below).

2. **A load profile, so the worker never pulls unlisted data into its own
   memory regardless of which credential it holds.**
   `database::TableLoadProfile` and `database::table_load_profile_includes`
   (`include/merovingian/database/persistent_store.hpp`) decide which tables
   `open_postgresql_persistent_store`'s row loader hydrates.
   `TableLoadProfile::federation_worker` is an **allowlist**
   (`database::federation_worker_table_allowlist`), not a denylist: a table
   absent from it is excluded by default, so a future migration's new table
   — secret-bearing or not — is unreadable by the worker until someone adds
   it to the allowlist deliberately. The full allowlist, derived by tracing
   every `FederationRuntimeState` callback the worker does NOT override to
   the `PersistentStore` field it reads (see the array's own doc comment in
   `persistent_store.hpp` for the file:line citation behind each row):

   | Table | Why the worker needs it |
   |---|---|
   | `rooms` | `make_join`/`make_leave`/`make_knock` templates, `query/directory`, space hierarchy |
   | `membership` | `query/directory` (servers joined to an aliased room), space hierarchy member counts |
   | `current_state` | membership-template auth_events, `room_version_resolver`, `room_server_acl_provider`, space hierarchy join-rule/space checks |
   | `events` | membership-template forward extremities, `backfill`, `state`, `state_ids`, `get_missing_events` |
   | `event_edges` | `reconstruct_event_relations` populates `PersistentEvent::prev_event_ids` from this table — without it, every event's prev_events read back empty for the routes above |
   | `event_auth` | same `reconstruct_event_relations` dependency, for `auth_event_ids` (auth-chain walks in `state`/`state_ids`) |
   | `event_signatures` | same `reconstruct_event_relations` dependency, for `PersistentEvent::signatures` |
   | `room_aliases` | `query/directory` (`find_room_alias`) |
   | `server_signing_keys` | remote-key caching (`remote_key_cache_probe`/`remote_key_resolver`) — **column-restricted**, see below |
   | `state_groups` | ADR-0064 phase A (0.12.13): the worker serves federation `/state` and `/state_ids` locally today from `current_state`/event relations; a later phase moves that to state groups, granted now so that phase needs no further role change |
   | `state_group_state` | same ADR-0064 phase-A reasoning, for a group's own delta/snapshot rows |
   | `event_state_groups` | same ADR-0064 phase-A reasoning, for the event → state group mapping |
   | `forward_extremities` | same ADR-0064 phase-A reasoning: the worker's membership-template forward-extremity read (currently derived from `events`) becomes sourced from here in a later phase |
   | `schema_migrations` | needed for ANY store to open (schema-version check via `load_schema_state`), not gated by `TableLoadProfile` at all |

   `server_signing_keys` needs a genuine caveat: the worker's remote-key
   cache legitimately reads and writes this table (caching *other* servers'
   public keys — `federation::find_cached_remote_key` /
   `store_server_signing_key`, `src/homeserver/local_http_router.cpp:1857-
   1871`), so excluding the whole table would break that. What must never be
   exposed is this server's *own* `secret_key` column. The fix is
   column-level, in two independent places: `load_persistent_rows`
   (`src/database/postgresql_store.cpp`) uses a worker-specific 4-column
   `SELECT` that never names `secret_key` at all, leaving
   `PersistentServerSigningKey::secret_key` empty for every worker-loaded
   row; and `provision-federation-worker-role.sql` grants
   `SELECT (server_name, key_id, public_key, valid_until_ts)` — a
   PostgreSQL column-level grant — so even a bug that widened the C++ query
   back to five columns would be refused at the database. The worker's
   *write* attempt (caching a freshly-fetched key) is expected to fail under
   this SELECT-only grant; the caller already discards that result
   (`std::ignore = cache_remote_server_keys(...)`,
   `src/federation/remote_key_cache.cpp`) and simply re-fetches on the next
   request, so the failure degrades performance, not correctness.

   Every table PersistentStore can hold that is **not** in the allowlist is
   read by NO worker-local code path — verified table by table during
   review (not merely "probably relayed"), listed in full under "Every
   table classified" below, since `TableLoadProfile` only gates the
   PostgreSQL loader and SQLite's own loader is never exercised by a test
   that could catch a wrong exclusion.

   **One dormant write path found during review:** `state_conflict_resolver`
   (`local_http_router.cpp:1255`, wired unconditionally by
   `wire_federation_callbacks`, never overridden by the worker) calls
   `database::store_state` — a write to `current_state` — when a PDU's
   ingestion result carries a populated `state_conflict`. In the worker,
   `pdu_sink` is *always* the IPC-relay override
   (`federation_worker::deserialize_pdu_ingest_result`), which never
   populates `PduIngestionResult::state_conflict`, so this resolver is
   registered but never actually invoked from inside the worker today. It
   is not relayed and not removed: `current_state` is already in the
   allowlist for reads, the write path is currently unreachable, and — were
   a future change to make it reachable — the SELECT-only grant would
   refuse the `INSERT`/`UPDATE` rather than silently succeed, so the
   failure mode stays fail-closed even if this invariant is ever broken by
   accident.

   `federation_worker_table_allowlist` (C++) and
   `provision-federation-worker-role.sql`'s per-table `GRANT SELECT` list
   are the two authoritative places for "which tables the worker can read"
   and must name the exact same set — `tests/unit/test_worker_db_uri.cpp`
   parses both from the source tree and asserts they match, so the two
   cannot drift silently.

### Every table classified

`tests/unit/test_worker_db_uri.cpp` also asserts every table
`migrations/*.sql` creates falls into exactly one of three buckets, so a new
migration's table cannot go unclassified:

- **Worker allowlist** (13 tables, profile-gated reads —
  `database::federation_worker_table_allowlist`): `rooms`, `membership`,
  `current_state`, `events`, `event_edges`, `event_auth`,
  `event_signatures`, `room_aliases`, `server_signing_keys`
  (column-restricted, see above), `state_groups`, `state_group_state`,
  `event_state_groups`, `forward_extremities` (the last four added in
  0.12.13 by ADR-0064 phase A — `state_groups` was vestigial before this and
  is now moved out of the never-reads list below).
- **Worker never reads** (43 tables): `users`, `devices`, `access_tokens`,
  `refresh_tokens`, `federation_destinations`, `federation_transactions`,
  `invites`, `state_transitions`, `sync_stream_watermark`,
  `event_stream_watermark`, `device_keys`, `one_time_keys`, `fallback_keys`,
  `cross_signing_keys`, `key_signatures`, `key_backup_versions`,
  `key_backup_sessions`, `media`, `media_blobs`, `remote_media`,
  `audit_log`, `admin_actions`, `policy_rules`, `account_data`,
  `room_account_data`, `to_device_messages`, `device_list_changes`,
  `presence_state`, `filters`, `profiles`, `account_threepids`,
  `client_txn_ids`, `pushers`, `notifications`, `openid_tokens`,
  `login_tokens`, `appservice_txn_cursor`, plus six tables `schema.cpp`
  declares but that no runtime code path (main's or the worker's) ever
  populates or queries — `event_json`, `key_backups`, `push_rules`,
  `rate_limits`, `room_versions`, `state_group_edges` — vestigial from
  earlier schema iterations, confirmed by grep to appear nowhere outside
  `schema.cpp`'s own DDL declarations. `state_group_edges` remains
  vestigial after ADR-0064 phase A: the design uses parent links on
  `state_groups` itself for the delta chain, not a separate edges table, so
  phase A deliberately left it alone. Whether to drop it is an open
  question for a later phase, not decided here.
  `federation_destinations`/`federation_transactions` specifically are read
  only by `federation::DispatchWorker`, which never starts in the worker
  process: its construction (`local_http_router.cpp`, guarded inside the
  same lazily-wired callback block) requires
  `runtime.database.signing_secret_key` to hold a real 32-byte secret, and
  the worker's runtime never loads one (`crypto_provider_overridden = true`,
  per ADR-0015/ADR-0062 part 1) — the construction check fails and returns
  before the worker ever touches either table, main or not. `profiles`,
  `device_keys`/`one_time_keys`/`fallback_keys`/`cross_signing_keys`/
  `key_signatures`, and `devices` are read only by
  `profile_query_provider`/`device_keys_query_provider`/
  `one_time_keys_claim_provider`/`user_devices_provider` — all four
  overridden by the worker to relay to main over IPC instead
  (`src/federation_worker/AGENTS.md` rule 3), so their default,
  table-reading implementations are wired but never invoked inside the
  worker.
- **Read by every process, not profile-gated** (1 table): `schema_migrations`.

**Explicit, logged opt-out:** `federation.worker.
allow_shared_database_credentials=true` lets the worker share main's login
when a separate role cannot be provisioned, restoring the pre-0.12.13-part-2
behaviour. `config::validate()` rejects `database.backend=postgresql` with
`security.federation.enabled=true` and an empty `database_uri_file` unless
this is set (`src/config/config.cpp`), and `homeserver::WorkerPool::
WorkerPool` logs `CRITICAL` on every startup while it applies, so the
downgrade cannot go unnoticed. Ignored entirely for
`database.backend=sqlite`: a single shared file offers no role boundary to
separate, so the worker keeps opening the same file there and the load
profile above is its only protection (see ADR-0062 part 2, "Positive
Consequences").

**Migration role never reachable from the worker.** The worker's own
connection always passes empty `runtime_role`/`migration_role` to
`open_postgresql_persistent_store` (cleared by `apply_worker_database_uri`),
so it can never `SET ROLE` to `:migration_role` even if a compromised worker
tried — and in the normal startup order the worker only ever connects after
main has already brought the schema to `current_schema_version()`, so the
migration branch inside `open_postgresql_persistent_store` (`schema.version <
current_schema_version()`) is unreachable from a worker connection in
practice regardless.

**No role is created by a migration.** PostgreSQL roles are cluster-level
objects, not part of any one database's schema, so — consistent with
`provision-roles.sql` — `provision-federation-worker-role.sql` is a
separate, operator-run provisioning script, never a file under
`migrations/`.

### Security audit follow-up (0.12.17)

Schema 18 adds `rooms.directory_public` as TEXT NOT NULL DEFAULT false. It is independent of room join rules; existing rooms remain unpublished because their prior publication intent was not durable (ADR-0099). Creation persists publication with the room and initial membership. Visibility changes commit before updating the store and runtime mirrors. PostgreSQL scoped snapshots bind one room ID and join relation tables to events, avoiding the 128-parameter ceiling for large rooms. Media moderation commits flags, removal blob state and required administrative audit rows together; mirrors change only after commit (ADR-0100).
