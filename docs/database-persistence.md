# Database persistence

This capability note describes the project-owned database persistence boundary,
the SQLite runtime backend, the PostgreSQL/libpq backend, and remaining work for
production operation.

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
  schema-state transitions, enabling backfill and corrective migrations
  should a later migration need one.
- The schema is a single step, version `1` (`initial_schema`):
  `schema::current_schema_version()` is `1`, and `migrations/` holds only
  `001_initial_schema.sql`. Every pre-1.0 migration (versions 2 to 26 as of
  0.12.46) was collapsed into it in 0.12.47
  ([ADR-0224](adr/0224-pre-1-0-migrations-collapse-into-one-frozen-v1-schema.md)),
  so v1 creates all 62 tables in their final shape, every column that an
  earlier migration used to `ALTER` on now being part of the table's `CREATE`,
  plus four indexes: `event_edges_prev_event_id`,
  `idx_to_device_messages_recipient_age`, `idx_deferred_pdus_room_id` and
  `idx_media_pending_uploads_owner`. Nothing is seeded or backfilled: the old
  state-transition backfill and state-group seeding only ever mattered for
  upgrading existing databases and no longer exist. The compiled catalog in
  `src/database/migration.cpp` has exactly one upgrade step (version `1`,
  `initial_schema`) and one downgrade step (to version `0`,
  `drop_initial_schema`, which drops every table).
  `migrations/001_initial_schema.sql` is the frozen record of v1; a unit test
  requires it to match the build's v1 step statement for statement.
- Schema change policy. Until `v1.0.0` there is nothing to upgrade from: a
  database whose `schema_migrations` ledger holds an upgrade row this build does
  not have (for example the rows 2 to 26 written by every build up to 0.12.46)
  is refused at open, before any migration or hydration
  (`schema_ledger_is_known`), and must be recreated. From `v1.0.0` the v1
  migration and `migrations/001_initial_schema.sql` never change; every schema
  change is a new numbered migration (v2 onwards) that keeps deployed databases
  compatible, and upgrade compatibility is promised from that release.
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
  `local_media_id` and `fetched_at_ms`.
- `room_aliases` carries `creator_user_id` (CSAZ-12, ADR-0127):
  `store_room_alias` writes the creating user, and `delete_room_alias` removes a mapping, in the database and
  in memory, for `DELETE /directory/room/{roomAlias}`.
- Binary payload columns are `BLOB` (#448): `media_blobs.bytes` holds raw media
  content and `server_signing_keys.secret_key` holds encrypted key material
  (`BLOB NOT NULL DEFAULT ''`, empty = no secret persisted). Both were folded
  into the v1 schema. SQLite
  column reads are length-based (`sqlite3_column_bytes`), so payloads
  containing NUL or invalid UTF-8 round-trip byte-exactly. `SchemaTableDefinition::columns_sql`
  is shared, backend-agnostic DDL text written in SQLite's dialect; PostgreSQL
  has no `BLOB` type, so `postgresql_store.cpp`'s `translate_ddl_types_for_postgresql()`
  rewrites `BLOB` to `BYTEA` (whole-word, so it cannot mangle an identifier)
  wherever a `SchemaTableDefinition` becomes DDL for that backend — both the
  bootstrap path and any later migration step.
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
  statement names; the checked-in `migrations/` directory contains only
  `001_initial_schema.sql`, the frozen record of the v1 schema.
- `sync_stream_watermark` table stores the highest allocated `sync_stream_id`
  and is updated by `database::allocate_sync_stream_id()` before the ID is
  used for ephemeral events such as typing notifications and read receipts. This
  prevents the monotonic sync stream counter from rolling back across restarts.
- `database::restore_sync_stream_id()` writes the highest `sync_stream_id` found
  in durable rows (account data, to-device messages, device-list changes,
  presence, read receipts) into the watermark on startup, so a restart starts from the
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
  exists even on a first start.
- `state_transitions` table records the previous `event_id` for every state-event tuple replacement.
  It is populated by `database::store_state()` and the split
  `prepare_store_event_with_state()` / `apply_store_event_with_state()` helpers.
  The in-memory store keeps a hash index over `state_transitions` so that
  `client_event_with_id()` can inject `unsigned.replaces_state` into the client
  event format in O(1) rather than scanning the whole vector. For federated
  state events the previous event ID is derived by walking the event graph
  (`prev_events` and `auth_events`) to find the predecessor state event of the
  same `(room_id, event_type, state_key)` tuple, instead of assuming the local
  arrival-time current state was the predecessor.
- `account_threepids` table records the 3PID bindings a user has
  added to their account, replacing the prior in-memory
  `vector<AccountThreePid>` which was lost on restart. Columns are `user_id`,
  `medium`, `address`, `country`, `id_server`, `added_at_ms`,
  `validated_at_ms`, and `bound`, with a unique key on `(medium, address)` so
  the same email/msisdn cannot be bound twice.
- `account_threepids.client_secret` / `account_threepids.sid` columns
  store the `client_secret` + `sid` pair the IS issued for a binding, so a later remote
  unbind can replay them in the request body (IS unbind auth mode 2). Both
  columns are `TEXT NOT NULL DEFAULT ''`; they are populated only for IS-bound
  3PIDs and left empty for local-only bindings.
- `PersistentThreePidBinding` struct (now carrying optional `client_secret`
  and `sid`) and the
  `store_account_threepid` / `find_account_threepid` /
  `delete_account_threepid` store functions
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  persist, look up, and remove bound 3PIDs. Implemented for both SQLite
  (`sqlite_store.cpp`) and PostgreSQL (`postgresql_store.cpp`); rows are
  hydrated into the in-memory store on backend open so existing bindings are
  visible immediately after restart.
- `pushers` table records the push notification pushers a user has registered via
  `POST /_matrix/client/v3/pushers/set`. Columns are `user_id`, `app_id`,
  `pushkey`, `kind`, `app_display_name`, `device_display_name`,
  `profile_tag`, `lang`, `data_url`, `data_format` (the pusher's `data`
  dictionary's `url`/`format` keys, stored as plain columns rather than
  nested JSON), and `data_extra_json` (a
  canonical-JSON-serialized object holding every OTHER member of the
  pusher's `data` dictionary at registration time; PR #479 review finding
  P1: the Push Gateway API's notify Device object is defined as "the data
  dictionary passed in at pusher creation minus the url key", so a custom
  member beyond `url`/`format` must survive a restart and reach the gateway,
  not just be discarded), with a primary key on `(user_id, app_id,
  pushkey)` — the spec's uniqueness rule: setting a pusher with the same
  `app_id` and `pushkey` for the same user replaces it in place. The `PersistentPusher` struct and the
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
- `notifications` table records the history
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
  re-parsing `actions`), with a primary key on `(user_id, event_id)`.
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
  `sync::read_receipt_markers()` against the caller's current `m.read`/
  `m.read.private` receipts in that room (unthreaded, or the one for the
  event's thread), so it always reflects the latest receipt without a
  write-side update on every receipt change.
  **Retention:** `store_notification` prunes the oldest rows for that
  `user_id` beyond `server.client_api.max_notifications_retained_per_user`
  (default 1,000, valid range 1..100,000), after every insert. The same policy
  applies to the in-memory mirror and SQLite/PostgreSQL persistence; rows with
  the oldest stream ordering are removed first. It is independent of
  `server.push.max_in_flight_deliveries`, which bounds background tasks rather
  than persisted rows. Recording still occurs when push delivery is disabled.
  Increasing retention preserves more future history but cannot restore rows
  already pruned under an earlier policy. Changing the policy requires restart.
- `openid_tokens` table stores the short-lived tokens minted by
  `POST /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19
  CS API §OpenID) and redeemed by `GET /_matrix/federation/v1/openid/userinfo`
  (SS API §OpenID). Columns are `user_id`, `token_hash` (primary key), and
  `expires_at` (epoch milliseconds, encoded the same way as
  `access_tokens.expires_at` / `refresh_tokens.expires_at` via
  `expires_at_text`/`parse_expires_at`). Unlike an access token's expiry,
  `expires_at` is never optional here — every OpenID token has a finite
  lifetime. This is a **separate table from `access_tokens`**,
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
- `login_tokens` table stores the short-lived, single-use
  tokens minted by `homeserver::complete_sso_login` when an SSO
  authentication completes (Matrix v1.19 CS API §"Client login via SSO")
  and redeemed exactly once by `POST /_matrix/client/v3/login` with `type:
  m.login.token` (`homeserver::redeem_login_token`). Columns are `user_id`,
  `token_hash` (primary key), `expires_at` (epoch milliseconds, same
  encoding as `openid_tokens.expires_at`), and `used` (`TEXT NOT NULL
  DEFAULT 'false'`, following the `revoked`-column boolean-as-text
  convention `access_tokens`/`refresh_tokens` already use).
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
- `appservice_txn_cursor` table persists the outbound
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
  The cursor is the *state of the one transaction
  in flight* (`pending_txn_id` / `pending_stream_ordering`) plus the
  transaction-ID allocator; the queue behind it is `appservice_outbox`
  below. A retry of the in-flight transaction reuses the exact same
  `pending_txn_id` and re-derives the identical single event from `events`,
  never growing it, per the spec's "Homeservers MUST NOT alter ... events
  they were going to send within that transaction ID on retries."
- `appservice_outbox` table (audit R01, ADR-0163) is the
  Application Service API transaction queue the spec requires: one row
  `(appservice_id, stream_ordering, event_id)` per event queued for one
  appservice, primary key `(appservice_id, stream_ordering)`. A row is
  written when the event is dispatched (`enqueue_appservice_event`,
  idempotent on the key, interest decided at that moment) and deleted in the
  same backend transaction that clears the cursor's pending transaction and
  raises `delivered_stream_ordering` (`complete_appservice_delivery`), so a
  crash can never leave a delivered event queued or a queued event
  forgotten. `stream_ordering` is `TEXT` like every numeric column in this
  schema; the in-memory mirror `PersistentStore::appservice_outbox` is kept
  sorted numerically by `(appservice_id, stream_ordering)`
  (`sort_appservice_outbox` after hydration). `delivered_stream_ordering` is
  now informational: it is **not** a threshold new events are compared
  against, because stream orderings are allocated before commit and events in
  other rooms commit out of order. Main process only: the table is not in
  `federation_worker_table_allowlist`. The queue of one appservice is capped at
  `appservice.max_queued_events` rows (default 100000, ADR-0191): at the cap
  `enqueue_appservice_delivery` writes no further row for that appservice, and
  `count_appservice_outbox_entries` (two binary searches over the sorted mirror)
  is what it checks. No row is dropped for age.
- `appservice_directory` table (ADR-0192) holds the rooms an
  appservice has published to the directory of one of its networks (protocols)
  with `PUT /_matrix/client/v3/directory/list/appservice/{networkId}/{roomId}`:
  one row `(appservice_id, network_id, room_id)`, primary key all three.
  `PersistentAppserviceDirectoryEntry`, `PersistentStore::appservice_directory`
  and `set_appservice_directory_entry` / `appservice_directory_contains` are
  implemented for both SQLite and PostgreSQL and hydrated on backend open;
  listing and unlisting are idempotent and commit before the mirror changes. It
  is independent of `rooms.directory_public`. Main only: the table is not in
  `federation_worker_table_allowlist`.
- `deferred_pdus` table (R03, ADR-0165) holds the federation PDUs
  `ingest_pdu_event` could not yet place because a `prev_event` or `auth_event`
  is unknown or a `prev_event` has no state group. Columns: `event_id`
  (primary key), `room_id` (indexed), `origin` (the server it arrived from, to
  backfill from), `pdu_json` (the envelope exactly as ingestion would have
  stored it, which is the redacted copy after a content-hash mismatch),
  `received_at_ms` (kept across attempts) and `attempts` (retries that did not
  place it). Every number is `TEXT`, like the neighbouring tables, and is parsed
  back at hydration. `PersistentDeferredPdu` and
  `upsert_deferred_pdu`/`remove_deferred_pdu`/`list_deferred_pdus`/
  `deferred_pdus_for_room`
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  are implemented for both SQLite and PostgreSQL, hydrated on backend open. The
  store is bounded: 100 rows per room, 1000 in total, 16 MiB of `pdu_json` in
  total (`max_deferred_pdus_per_room`, `max_deferred_pdus_total`,
  `max_deferred_pdu_json_bytes`); a new row that would exceed one is refused
  (`DeferredPduUpsert::refused_full`) while an update of a held row never is.
  Rows older than 24 hours (`max_deferred_pdu_age`) or retried 10 times
  (`max_deferred_pdu_attempts`) are dropped by
  `homeserver::retry_deferred_pdus` and audited. The next-attempt time is not
  stored (`HomeserverRuntime::deferred_pdu_next_attempt`, in memory): after a
  restart every retained PDU is due at once. Main only: the table is not in
  `federation_worker_table_allowlist`, because the worker relays every PDU to
  main and never reads or writes it.
- `receipts` table (ADR-0169) holds read receipts, local and federated: one row per
  `(room_id, receipt_type, user_id, thread_id)` (the primary key), naming
  `event_id`, its `ts` and the `stream_id` it was last set at. `thread_id` is
  `''` for an unthreaded receipt, `main` for the main timeline, or a thread
  root's event ID. Every unread count is computed from these rows, so before
  this table a restart marked every room unread. `PersistentReceipt`,
  `PersistentStore::receipts` and `store_receipt`/`remove_receipt`
  ([persistent_store.hpp](../include/merovingian/database/persistent_store.hpp))
  are implemented for both SQLite and PostgreSQL and hydrated on backend open;
  `store_receipt` allocates the sync stream position and commits the row before
  the mirror changes. At the inbound cap, it deletes the selected victim and
  upserts the incoming receipt in one transaction. A failed delete or upsert
  preserves the previous receipts in both the database and the mirror.
  The inbound receipt callback takes `HomeserverRuntime::mutex`
  before checking membership or reading/updating the receipt mirror, including on
  direct federation requests; worker relays can re-enter this recursive lock.
  Only `m.read` and `m.read.private` are stored here:
  `m.fully_read` is room account data. Inbound federated receipts are capped by
  `homeserver::max_inbound_receipt_entries`; at the cap the oldest receipt of a
  *remote* user is removed, never a local user's. Main only: the table is not in
  `federation_worker_table_allowlist`.
- The v1 schema's media tables carry the upload names and pending uploads.
  - `media.upload_name` (`TEXT NOT NULL DEFAULT ''`, ADR-0211) is the upload's `filename`
    (or the remote server's `Content-Disposition` filename), served back in
    `Content-Disposition`.
  - `media_pending_uploads` (`media_id` primary key, `owner_user_id`, `created_at_ms`,
    `expires_at_ms`, indexed by owner; ADR-0212) holds the `mxc://` URIs reserved by
    `POST /_matrix/media/v1/create` that have no content yet. `commit_pending_media_upload`
    inserts one and deletes the expired ones it was handed in the same transaction;
    `commit_local_media_upload` with `completes_pending_media_id` deletes the row in the
    transaction that stores the content. Rows are bounded by `max_pending_uploads`. Main only:
    not in `federation_worker_table_allowlist` (the federation media route runs in main).
- `users.deactivated` column (part of the v1 schema) is a `TEXT NOT NULL DEFAULT
  'false'` column of the `users` table, set by
  `POST /_matrix/client/v3/account/deactivate` (see `docs/auth-identity.md`
  "Account deactivation"). It is deliberately distinct from the existing
  reversible `locked`/`suspended` columns: a deactivated account can never
  log in again, and its row is retained (not deleted) so the localpart is
  never reissued to a new registration. `set_user_deactivated`
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
- **Phase A of spec-conformant PDU ingestion (ADR-0064): delta state groups,
  forward extremities, and event status.** This is storage plumbing only —
  it does not change how PDUs are ingested, how local events pick
  `prev_events`, or what clients see; that is later phases. The v1 schema
  holds:
  - `events.status` — `TEXT NOT NULL DEFAULT 'accepted'`, one of
    `'accepted' | 'soft_failed' | 'rejected' | 'outlier'` (spec: "Checks
    performed on receipt of a PDU"). `set_event_status`/`find_event_status`
    get/set it, validating the value and mirroring the change into the
    in-memory `PersistentEvent::status` field (appended as that struct's
    last member, defaulting to `"accepted"`, so no existing brace-init call
    site needed to change).
  - `state_groups`, the root of a delta chain, with `parent_state_group_id`
    (`TEXT NOT NULL DEFAULT ''`) and `delta_depth` (`TEXT NOT NULL DEFAULT
    '0'`). Like every other nullable-in-spirit column in this
    schema (e.g. `state_transitions.previous_event_id`), the empty string is
    the "no parent, this is a snapshot" sentinel rather than a SQL `NULL` —
    `PreparedStatement`/`BoundValue` has no NULL parameter representation,
    and this keeps the convention consistent with the rest of the schema.
    In C++, `PersistentStateGroup::parent_state_group_id` is
    `std::optional<std::string>` (`nullopt` ⇔ the empty-string sentinel).
    `state_group_edges` is vestigial and unused — see "Federation worker
    least-privilege role" below for whether it should eventually be dropped.
  - `state_group_state (state_group_id, event_type, state_key, event_id)` —
    one group's own rows: the full state for a snapshot group
    (`parent_state_group_id` empty), or just the changed entries for a
    delta group.
  - `event_state_groups (event_id PRIMARY KEY, state_group_id)` — maps an
    event to the group holding the room's state immediately after it.
  - `forward_extremities (room_id, event_id)` — a room's current DAG
    leaves.
  - **Index:** `event_edges_prev_event_id ON event_edges (prev_event_id)`.
    `event_edges`' primary key is `(event_id, prev_event_id)`, which cannot
    serve a lookup keyed on `prev_event_id` alone; the ingest-time "children
    of this event" lookup (is this event anybody's `prev_event_id`?) needs
    exactly that shape, and without the index it is a full table scan per
    probe. Confirmed by `EXPLAIN QUERY PLAN` in
    `tests/integration/test_state_groups_flow.cpp`'s "event_edges has a
    usable index for prev_event_id lookups in the v1 schema" scenario.
    `state_groups` has no matching `room_id` index: every store function that
    reads it (`find_state_group`, `read_state_group_full_state`,
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

  A fresh database starts with no state groups or forward extremities; they are
  written as rooms are created and events ingested. Nothing is seeded at
  bootstrap. PostgreSQL bootstrap creating these tables is covered by
  `tests/integration/test_state_groups_flow.cpp`.

- **Phase B1 of spec-conformant PDU ingestion (0.12.13, ADR-0064): the phase
  A tables are now written and read on the live ingest path**, not just
  declared in the schema. New module
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
  have not fetched yet. Since R03 (ADR-0165) the PDU is also retained in
  `deferred_pdus` and the status is `deferred`; `missing_prev_state` is what
  is left when nothing could be retained); the after-state group, forward-extremity update,
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
    `database::store_event_with_state` directly. Since 0.12.48 the state
    before is resolved once, while the event is composed
    (`homeserver::basis_for_new_event`), and handed to `store_local_event`
    as a `NewEventBasis`; when the extremities' states do not resolve, the
    basis cites only the newest extremity whose state reads alone, and its `retired_extremities`
    leave the `forward_extremities` table with the event (ADR-0225).
  - `local_http_router.cpp`'s `membership_acceptor` (a remote user's
    `send_join`/`send_leave`/`send_knock` into a room we are resident in —
    the same trust boundary as `ingest_pdu_event`) gets the identical
    state-before check and after-state/current-state bookkeeping.
    `invite_handler`'s invite-event store gets explicit `status =
    "outlier"` (it is never part of this server's own timeline).
  - Since 0.12.48 (ADR-0228) a local event and a federated join commit in ONE
    transaction with all of their bookkeeping, through
    `homeserver::store_event_with_bookkeeping`: the event with its
    `current_state` row and membership projection, its after-state group, the
    mapping, the forward-extremity change, and every `current_state` change
    the resolution of the new extremities makes. Each part has a prepared form
    in the store (`prepare_store_event_with_state`, `prepare_state_group`,
    `prepare_event_state_group`, `prepare_forward_extremities_update`,
    `prepare_current_state`) and an `apply_*` that mirrors it in memory once
    the transaction commits; the single-step functions
    (`create_or_reuse_state_group`, `set_event_state_group`,
    `update_forward_extremities`, `store_state`) are prepare, commit, apply. A
    refusal at any part writes nothing. Before, each part committed on its own,
    so a 500 could leave the event stored and the room's tip moved, or a user
    joined with no state group. Inbound PDUs keep their separate commits.
  - The federated-join flow (`join_room`/`perform_federated_join`,
    `room_service.cpp`) seeds the room's state from the
    `send_join` response's state (stored as `status = "outlier"` events by
    `ingest_send_join_state`, which returns the full state map alongside
    the joined-members list): the join event's after-state, that state plus
    the join, is one snapshot group (until 0.12.48, a delta on a separate
    `join-snapshot:` group holding the before-join state, which nothing
    read), and the join is made the room's sole forward extremity (since
    0.12.48 it also retires every extremity an earlier stay left; before, a
    rejoin kept them) — so the first inbound PDU
    after a join no longer hits `missing_prev_state`. Since FED-1
    (ADR-0083) only entries whose room is the joined room are stored, and
    `auth_chain` events are stored as outliers with no `current_state` row;
    `repair_missing_state_entries` (start-up) likewise only promotes
    `accepted` events, never an outlier or a rejected one.
  - A source-tree guard test (`tests/unit/test_store_event_choke_point.cpp`)
    fails the build if `database::store_event_with_state(` appears anywhere
    in `src/` outside a reviewed, counted allowlist, and since 0.12.48 the
    same for `database::prepare_store_event_with_state(`.
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
- **Token rotation lineage (ADR-0074).** `refresh_tokens.predecessor_hash` and
  `access_tokens.predecessor_refresh_hash` (both `TEXT NOT NULL DEFAULT ''`) are
  part of the v1 schema. A token pair minted by `POST /refresh` records the hash
  of the refresh token it replaced, which stays valid until the pair is first
  used (see `docs/auth-identity.md`). Both backends store and hydrate the
  columns; `database::revoke_refresh_tokens_with_predecessor` supersedes an
  unused pair when a refresh is retried. Hydration
  (`homeserver::hydrate_local_database`) also copies each access token's
  `expires_at` into its session; before 0.12.13 it did not, so expiry was not
  enforced after a restart.
- **M05 authenticated-media storage
  ([ADR-0068](adr/0068-random-media-ids-and-legacy-endpoint-freeze.md)).**
  The `media` table's `legacy_endpoint_visible` column (`TEXT NOT NULL DEFAULT
  'true'`) is part of the v1 schema. New local uploads are stored with
  `legacy_endpoint_visible = false` (see `docs/media-repository.md`); the
  unauthenticated `/_matrix/media/v3/download` and `/thumbnail` routes treat a
  `false` value as a 404, while authenticated `/_matrix/client/v1/media/...`
  routes ignore it and serve the media. Adding a column to the `media` table
  does not affect the federation worker table classification: `media` remains
  in `worker_never_reads_tables`, so the worker allowlist needs no change.
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
- Upgrade coverage (`tests/integration/test_database_upgrade_flow.cpp`, ADR-0216,
  ADR-0224). `migrate_sqlite_schema_to` and `migrate_postgresql_schema_to` build a
  schema at an older version and stop there: they bootstrap an empty database,
  apply migrations forward to exactly the target, and hydrate nothing. They refuse
  a version this build does not know before touching the database, and a schema
  already past the target, since migrations never run backwards. Today the
  catalog has only v1, so the scenarios cover the v1 build-and-stop seam, never
  going past this build, an unopenable file being refused, tables without a ledger
  being refused (SQLite), a fresh database having every table's final columns and
  all four indexes, and a pre-1.0 ledger (rows 2 to 26) being refused on both
  backends. The "any older version opens at current" scenario is vacuous until a
  v2 exists. There is no previous-release fixture: the 0.11.13 fixture was
  removed when the migrations collapsed (0.12.47, ADR-0224). When the 1.1 series
  starts, the last 1.0.x release writes the next fixture with
  `scripts/generate_upgrade_fixture.py` (see `docs/release-process.md`).
- Both stores read the migration ledger in numeric order
  (`ORDER BY CAST(version AS INTEGER)`): `schema_migrations.version` is `TEXT`, and
  ordering by it alone put `'10'` before `'9'`.
- The PostgreSQL store hydrates `profiles` like the SQLite store. Before 0.12.42 it
  wrote them but never read them back, so displaynames and avatars disappeared at
  every restart.
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
- `PUT /sendToDevice` writes its local `to_device_messages` rows and its
  `client_txn_ids` row in ONE backend transaction
  (`database::enqueue_to_device_messages_with_client_txn`, R02, ADR-0164). The
  per-recipient age and count evictions (CSAZ-10, ADR-0117) are part of that
  transaction: `enqueue_to_device_message` and the batched function share one
  prepare step that builds the DELETE/INSERT statements without touching
  memory, and the in-memory mirror is updated only after the commit succeeds.
  A failed commit leaves the store unchanged and the transaction unrecorded, so
  the handler answers `500 M_UNKNOWN` and a retry with the same transaction ID
  is processed rather than replayed. Stream ids are allocated before the commit
  (`allocate_sync_stream_id` persists the watermark itself); a failed commit
  skips them, it never reuses them. A request with no local recipient records
  the transaction alone through the same function.
- An inbound `m.direct_to_device` EDU writes all of its `to_device_messages` rows in ONE backend
  transaction (`database::enqueue_to_device_messages`, ADR-0166), through the same prepare/apply
  steps and evictions as the single-message and `/sendToDevice` writers. A failed commit stores
  none of the EDU, and the sink records its `(origin, sender, message_id)` in the in-memory
  replay window only after the commit, so the origin's resend is delivered in full.
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
  runtime state is hydrated. A database whose `schema_migrations` ledger holds an
  upgrade row this build does not know (for example the rows 2 to 26 written by
  pre-1.0 builds up to 0.12.46) is refused at open, before any migration or
  hydration (`schema_ledger_is_known`), on both backends.
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
  key/value form. **Connection-opening diagnostics (DB-9)** use a fixed redacted
  identity and generic parser/connection-status refusal reasons rather than
  reconstructing a supplied option summary or forwarding library error text.
  Host/database values are suppressed too because they can contain sensitive
  material. The existing unit checks pass 6 / 1; new actual DEBUG-console
  coverage passes 85 / 2, including malformed quoted options and four admitted
  quoted/spaced/escaped/URI forms reaching a real libpq failure against an owned
  private nonexistent socket path. It checks required records, whole/partial
  marker absence, returned identity/reason and environment/stdout/owned-path
  restoration. Normal database integration passes 2628 / 58; these are
  first-GREEN coverage of the existing guard, not a new production repair.
  Bounded independent source review passed without security or logic findings;
  reviewed files match executed manifests. Current database units pass 18363 / 174,
  DB-8 units 48 / 2 and DB-6 integration 2733 / 15. Fresh combined acceptance
  passed 56 OK targets with all return codes zero, no failures/timeouts and 139
  unchanged snapshotted files including all 30 focused sources. Source freeze
  ended after completed-archive/current-source inspection. Native Windows socket
  execution, live authentication/TLS/ready branches and
  general SQL-result error confidentiality are not established by these checks.
  See [ADR-0139](adr/0139-suppress-postgresql-connection-options-in-diagnostics.md).
- **Remote PostgreSQL TLS admission (DB-8):** every effective host and host-address
  entry is checked. Unless all destinations are local Unix sockets or recognized
  loopback literals, parsed connection options must explicitly select `sslmode`
  with the value `verify-full`. An omitted or empty mode cannot inherit its way
  through admission via `PGSSLMODE`; the minimal worker environment deliberately
  excludes that default. Service indirection and insecure remote opt-outs remain
  unsupported. The opener disables preferential GSS encryption and database-name
  expansion; private credential readers, role handling, binary bindings and
  transaction semantics are unchanged. Certificate trust and sandbox accessibility
  must be provisioned for each process. The new deterministic unit regression
  failed 4 / 28 assertions before repair and passes 28 / 1 afterward; all DB-8
  checks pass 48 / 2 and database units pass 18363 / 174. Live TLS/hostname/certificate
  refusal and worker trust-file access are not proven by admission tests;
  independent source review passed without security or logic findings. Fresh
  combined acceptance passed 56 OK targets with all return codes zero, no
  failures/timeouts and 135 unchanged snapshotted files, including all focused
  sources; the source freeze ended after acceptance. Normal DB-6
  integration passes 2733 / 15 and both isolated PostgreSQL modes pass 178 / 2
  with verified teardown, fixture removal and current-source binding; these
  local compatibility checks do not establish remote TLS transport. See
  [ADR-0138](adr/0138-require-explicit-remote-postgresql-tls-policy.md).
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

The v1 `push_rules` schema table remains unused: a user's push rules are kept as
their `m.push_rules` global account data, applied over the current server defaults
(ADR-0204), because that table's primary key cannot express a rule's kind. Federation queue
tables (`federation_destinations`, `federation_transactions`) are hydrated and
used by the runtime on both backends; media metadata and policy rows are also
persisted and hydrated.

## Next starting points

- `merovingian-db-migrate` (`src/db_migrate.cpp`) remains an offline planning
  tool: it prints a migration plan and does not connect to a database. Runtime
  startup applies pending schema migrations automatically.
- PostgreSQL role separation is enforced in the live server path. When roles
  are configured, `open_postgresql_persistent_store()` assumes
  `database.migration_role` for DDL (the fresh-database v1 bootstrap and any
  later pending migration), resets it, and then assumes
  `database.runtime_role` for runtime access. The fresh-database bootstrap
  fails closed if the migration role cannot be assumed, so the migration role
  owns every table on a fresh install; a single-role deployment (no migration
  role) bootstraps as the login role. Live role scenarios run in the
  `postgres-integration` workflow because they require PostgreSQL and the role
  environment variables. See `packaging/postgresql/provision-roles.sql`.
- The schema's v1 `push_rules` table is unused: push rules are kept as `m.push_rules`
  account data (ADR-0204, see above). The configuration key
  `server.identity_server.allowed_bind_domains` is accepted but currently read
  by no bind or `requestToken` path, so it is not enforced.

## Federation worker least-privilege role (ADR-0062 part 2)

The out-of-process federation worker (`merovingian-fed-worker`,
`src/federation_worker/`) is the process most exposed to hostile input (see
`src/federation_worker/AGENTS.md`). Before 0.12.13 finding N1 part 2, it
opened the database with the *same* PostgreSQL login as main, so a
compromised worker could `SELECT` `server_signing_keys.secret_key` (still
ciphertext, but exactly what decrypts it once the operator master key is
recovered by an unrelated bug — see ADR-0062 part 1) and every other
credential-bearing table, even though no worker code path ever reads them.

**Do not use `peer` authentication for main's role** (ISO-8, ADR-0147). The
worker runs under main's uid, and Landlock does not govern `connect()` to a
Unix socket, so a compromised worker can reach PostgreSQL's local socket; with
`peer` (or `ident`) PostgreSQL would log it in as main's role on the uid alone,
undoing the separate login below. Use `scram-sha-256` or certificate
authentication for both roles.

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

2. **A load profile for PostgreSQL-backed workers.**
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
   this SELECT-only grant, as it does on SQLite, where the worker's connection
   is read-only. The resolver therefore returns the key it fetched and verified
   directly, never a read-back of the cache (ADR-0238, 0.12.59); before that it
   read the key back after the failed write, found nothing, and refused every
   server the worker had not cached at start-up. The worker keeps a resolved
   remote in its in-memory `runtime.remotes`, so the failed write costs at most
   one fetch per server and key per worker start.

   Every table `PersistentStore` can hold that is **not** in the allowlist is
   read by no worker-local code path — verified table by table during review
   and listed under "Every table classified" below. This code-path audit is
   separate from what the backend hydrates: the profile gates PostgreSQL
   hydration only. SQLite's `open_sqlite_persistent_store()` accepts a profile
   but currently uses it only to open the database read-only for the worker;
   `load_persistent_rows()` then uses the full loader without applying the
   allowlist. Consequently, a SQLite-backed federation worker holds data such
   as user password hashes, token hashes and stored signing-key ciphertext
   that the PostgreSQL worker profile excludes. Media blob bytes remain
   read-on-demand rather than all being hydrated.
   Read-only mode prevents writes to the file; it does not provide this
   in-memory least-privilege boundary. This remains an open gap requiring
   profile-aware SQLite hydration and a regression test.

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
- **Worker never reads** (47 tables): `users`, `devices`, `access_tokens`,
  `refresh_tokens`, `federation_destinations`, `federation_transactions`,
  `invites`, `state_transitions`, `sync_stream_watermark`,
  `event_stream_watermark`, `device_keys`, `one_time_keys`, `fallback_keys`,
  `cross_signing_keys`, `key_signatures`, `key_backup_versions`,
  `key_backup_sessions`, `media`, `media_blobs`, `remote_media`,
  `audit_log`, `admin_actions`, `policy_rules`, `account_data`,
  `room_account_data`, `to_device_messages`, `device_list_changes`,
  `presence_state`, `filters`, `profiles`, `account_threepids`,
  `client_txn_ids`, `pushers`, `notifications`, `openid_tokens`,
  `login_tokens`, `appservice_txn_cursor`, `appservice_outbox`, `deferred_pdus`,
  `receipts`, `appservice_directory`, `media_pending_uploads`, plus six tables `schema.cpp`
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
`database.backend=sqlite`: a single shared file offers no PostgreSQL role
boundary. The SQLite connection is read-only in the worker, but the current
SQLite row loader uses full hydration and does not enforce the worker table-load
profile. The profile therefore is not an in-memory protection on SQLite yet
(see the open gap above and ADR-0062 part 2, "Positive Consequences").

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

`rooms.directory_public` is `TEXT NOT NULL DEFAULT 'false'` in the v1 schema. It is independent of room join rules; publication is an explicit, durable choice (ADR-0099). Creation persists publication with the room and initial membership. Visibility changes commit before updating the store and runtime mirrors. PostgreSQL scoped snapshots bind one room ID and join relation tables to events, avoiding the 128-parameter ceiling for large rooms. Media moderation commits flags, removal blob state and required administrative audit rows together; mirrors change only after commit (ADR-0100).

### Membership rows commit with their event (DB-4, 0.12.26)

`database::MembershipProjection` carries the `membership` row, and the invite metadata change, that an
`m.room.member` event implies. `store_event_with_state` and `prepare_store_event_with_state` take one and
write it in the event's own transaction (an upsert on `membership`, and an upsert or keyed delete on
`invites`), so the event, its `current_state` row, the row and the invite change are durable together or
not at all, on both backends. `store_membership_projection` writes a row and invite change with no event in
one transaction. `reconcile_memberships_with_current_state` runs at main's hydration (`TableLoadProfile::full` only; the federation worker never writes main's rows): a row is rewritten to the
current member event's membership when the row is missing, says `join` while the event does not, or is older
than the event; a newer row is kept. Corrected rows get a fresh stream ordering and are corrected in memory
even if the write fails. No schema change (ADR-0149).

### Write connection pool (DB-7, 0.12.26)

Persisted writes reuse connections from a per-store `ConnectionPool` instead of opening one per
transaction: at most `database.pool_size` (16) are in use at once, and a write waits for a free one.
PostgreSQL connections assume the runtime role once when opened; a pooled one is reused only while idle
(`PQTRANS_IDLE`) with nothing to read on its socket, so one the server has closed is replaced. SQLite
connections keep their pragmas and `foreign_keys=ON`. Reads, migrations and the worker's read-only store
still open their own connections. `write_connections_opened` reports how many the pool has opened
(ADR-0154). A slot is given back on every way out of an acquisition, a throwing open or liveness check
included: waiting for a slot has no timeout, so a slot that leaked would be lost for good.

An SQLite database file is created `0600` and must not be a symlink. Directories that already exist are
followed as the kernel resolves them, symlinks included (an operator's `/var/lib/merovingian` pointing at a
data volume); any directory the server creates is made `0700`, and everything below it is opened without
following links (DB-10).

Those checks never open an existing database file: closing any descriptor of it would release every POSIX
lock the process holds on it, including another connection's write lock (ADR-0157). An existing file is
checked by name (`fstatat` with `AT_SYMLINK_NOFOLLOW`), and a read-only connection reads the header, to
refuse WAL, through SQLite's own handle before any statement runs.

A read-only connection (the worker's store and room reloads, media blob and audit reads) can be told a
journal is hot when it is not: SQLite checks that the journal exists and then that no process holds
RESERVED, and a writer that commits between the two checks has already deleted its journal and unlocked.
A read-write connection settles that under EXCLUSIVE; a read-only one fails at once with
`SQLITE_READONLY_ROLLBACK`. The open-time pragmas, `prepare` and every read's first step retry that one
result every 10 ms for up to 2 s; a journal that is really hot still fails the read, and main's next
read-write connection rolls it back (ADR-0159). A failed room snapshot logs `room_snapshot.read_failed`
with its stage and extended SQLite code, and a connection whose open-time pragmas fail logs
`connection.rejected` with the code.

A room reload (`reload_room`) reads the room's eight tables in one read transaction, so its rows
come from one committed state: `BEGIN DEFERRED` on SQLite, whose first read takes SHARED until the
end (main's commits wait for it), and `REPEATABLE READ READ ONLY` on PostgreSQL. The worker's
whole-store startup load stays one statement per table, so it never holds SQLite's SHARED lock for
the whole load (ADR-0161).

### Event table indexes (0.12.39)

`PersistentStore::events` is a `database::EventTable` (`include/merovingian/database/event_table.hpp`),
not a `std::vector`. It owns the in-memory rows of the `events` table and keeps two indexes over them,
both holding positions in its row vector so they survive reallocation (ADR-0215):

- **by event ID.** `events.find(id)` and `events.contains(id)` are hash lookups, and
  `events.find_in_room(room_id, id)` adds the room check. `events.with_id(id)` is a range of zero or
  one rows, for a loop whose body runs for the match. Use these, never a `find_if` over the rows.
- **by stream order.** `events.in_stream_order()` visits every row by ascending `stream_ordering`. Rows
  with equal stream orderings come in the order they were added. Reverse it for newest first. Iterating
  the table itself visits arrival order, which is not stream order: SQLite hydration has no `ORDER BY`,
  PostgreSQL hydrates in event-ID order and moves a row whose status is updated, and stream orderings
  commit out of order across rooms.

Rows are read-only through the table. The only ways to change it are:

| Change | Method | Callers |
|---|---|---|
| Add one event (refused if its ID is already held) | `insert()` / `push_back()` | `store_event`, `apply_store_event_with_state` |
| Add many, sorting their stream order in one pass | `insert_all()` | SQLite and PostgreSQL hydration, `reload_room`, room snapshots |
| Change a row's fields other than `event_id` and `stream_ordering` | `modify()` | `set_event_status`, `replace_event_json` (redaction), `reconstruct_event_relations` |
| Remove rows, renumbering both indexes in one pass | `erase_if()` | `reload_room` |
| Move every row out | `extract()` | room snapshot loaders |

`modify()` puts `event_id` and `stream_ordering` back if a mutation changes them. The table has no lock
of its own: like every other `PersistentStore` member, it is guarded by `runtime.mutex` in the homeserver.
