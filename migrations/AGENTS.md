# migrations/ — SQL Migrations

Migrations run exactly once, in ascending numeric order, and **must never be modified
after they have been applied to any environment**.

## File naming

```
NNN_snake_case_description.sql
```

`NNN` is a zero-padded three-digit integer: `001`, `002`, ..., `010`, `011`, ...
The next migration number is always `max(existing) + 1`.
Current highest: `014`.

Schema version `2` introduced the `sync_stream_watermark` table via
`002_sync_stream_watermark.sql` to support live pre-production deployments that
must upgrade in place. Schema version `3` adds the analogous
`event_stream_watermark` table via `003_event_stream_watermark.sql` so the
timeline stream_ordering counter survives restarts. Schema version `4` adds
the `state_transitions` table via `004_state_transitions.sql` so the server can
populate `unsigned.replaces_state` when serving state events to clients. Schema
version `5` (`005_backfill_state_transitions.sql`) is data-only and backfills
the `state_transitions` rows for pre-existing rooms; it adds no tables. Schema
version `6` adds the `account_threepids` table via `006_account_threepids.sql`
so durable 3PID bindings (medium/address, optional country and identity server,
validation/bound timestamps) survive restarts. Schema version `7`
(`007_account_threepids_columns.sql`) adds the `client_secret` and `sid`
TEXT columns onto `account_threepids` so the homeserver can persist the
identity-server credentials needed for IS-delegated unbind (auth mode 2:
sid + client_secret); it adds no new tables. Schema version `8`
(`008_pushers.sql`) adds the `pushers` table so push notification pushers
registered via `POST /_matrix/client/v3/pushers/set` survive restarts, keyed
on `(user_id, app_id, pushkey)` per the spec's uniqueness rule. Schema
version `9` (`009_notifications.sql`) adds the `notifications` table so
`GET /_matrix/client/v3/notifications` history survives restarts, keyed on
`(user_id, event_id)`; `stream_ordering` doubles as the endpoint's `from`/
`next_token` pagination key, and rows are pruned per-user at write time (see
`docs/database-persistence.md`) so the table cannot grow without bound.
Schema version `10` (`010_openid_tokens.sql`) adds the `openid_tokens` table
so tokens minted by `POST /_matrix/client/v3/user/{userId}/openid/request_token`
(Matrix v1.19 CS API §OpenID) survive restarts and can be redeemed by `GET
/_matrix/federation/v1/openid/userinfo` (SS API §OpenID). It is deliberately
a separate table from `access_tokens`: an OpenID token is a narrow,
short-lived credential good only for the federation userinfo lookup, and
must never be usable as a client-server bearer token — see
`docs/threat-model.md`. Every row has a finite `expires_at`; expired rows
are pruned at write time (see `docs/database-persistence.md`) so the table
cannot grow without bound. Schema version `11` (`011_pushers_data_extra.sql`)
ALTERs `data_extra_json` onto `pushers` (no new table): a canonical-JSON
object holding every member of a pusher's registration-time `data`
dictionary beyond `url`/`format`, which already have dedicated columns.
Matrix v1.19 Push Gateway API requires forwarding the pusher's whole `data`
dictionary minus `url` to the gateway, not just `format`; see
`docs/database-persistence.md`. Schema version `12` (`012_login_tokens.sql`)
adds the `login_tokens` table so short-lived, single-use SSO login tokens
minted by `homeserver::complete_sso_login` (Matrix v1.19 CS API §"Client
login via SSO") survive restarts and can be redeemed exactly once by `POST
/_matrix/client/v3/login` with `type: m.login.token`. It is deliberately a
separate table from `access_tokens`, for the same token-confusion reason
`openid_tokens` is — see `docs/threat-model.md`. Every row has a finite
`expires_at` and a `used` flag; expired-or-used rows are pruned at write
time (see `docs/database-persistence.md`) so the table cannot grow without
bound. After `v1.0.0`, deployed databases become a
strict compatibility boundary and schema changes must be added as new
forward migration files instead of modifying already-applied migrations.
Schema version `12` (`012_login_tokens.sql`) adds the `login_tokens` table
for SSO login token redemption — owned by a sibling feature branch (not
implemented in this codebase's C++ layer); it is registered here purely so
this branch's own migration chain has no version gap. Schema version `13`
(`013_appservice_txn_cursor.sql`) adds the `appservice_txn_cursor` table:
one row per registered appservice, tracking the Application Service API's
outbound `PUT /_matrix/app/v1/transactions/{txnId}` delivery cursor
(`next_txn_id`, `delivered_stream_ordering`) plus the currently in-flight
(unacknowledged) batch, if any (`pending_txn_id`/`pending_stream_ordering`)
— see `docs/database-persistence.md` and `src/homeserver/room_service.cpp`'s
appservice delivery dispatch for how retries reuse the same `pending_txn_id`
and event range rather than growing it, per the spec's "Homeservers MUST NOT
alter ... events they were going to send within that transaction ID on
retries."

  Schema version `14` (`014_user_deactivation.sql`) adds a `deactivated` TEXT
column to `users`, defaulting to `'false'`, so `POST
/_matrix/client/v3/account/deactivate` can close an account permanently. It is
deliberately distinct from the existing reversible `locked`/`suspended` admin
flags: a deactivated account can never log in again, and its row is retained so
the localpart is never reissued. Adding the column also required naming the
columns explicitly in `insert_user` — the previous bare `INSERT INTO users
VALUES (...)` would have broken silently on the sixth column.

## File format

```sql
-- merovingian-migration version=N name=snake_case_description direction=upgrade
-- statement snake_case_statement_name
SQL STATEMENT
-- statement next_statement_name
NEXT SQL STATEMENT
```

- `version=N` matches the numeric prefix (no leading zeros in the integer, e.g. `version=5` for `005_...`)
- Each statement preceded by `-- statement <name>` on its own line
- Statement names must be unique within the file and descriptive (`events_add_stream_ordering`, not `stmt1`)
- No trailing semicolons — the migration runner adds them

## Safety rules

1. **Never modify an existing production migration.** Write a new one instead.
   Before `v1.0.0`, keep schema churn folded into `001_initial_schema.sql`
   because there are no supported live production databases to upgrade.
2. **Never drop a column or table** without explicit user approval — data loss is irreversible.
3. **Always provide a DEFAULT when adding NOT NULL columns** to existing tables — both SQLite
   and PostgreSQL require this for non-empty tables.
4. **Test on a populated database** before merging: run `python build.py` and verify the server
   starts cleanly against an existing database file.

## Schema source of truth

The canonical schema description lives in `docs/database-persistence.md`.
Update that document whenever a migration changes the schema.
