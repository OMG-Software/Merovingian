-- SPDX-FileCopyrightText: 2026 James Chapman
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- PostgreSQL role provisioning for the out-of-process federation worker
-- (ADR-0062 part 2, docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md).
--
-- The federation worker (merovingian-fed-worker) is the process most exposed
-- to hostile input (see src/federation_worker/AGENTS.md). Before this script
-- it connected to PostgreSQL with the SAME login role as main, so a
-- compromised worker could SELECT server_signing_keys.secret_key (still
-- ciphertext, but the ciphertext is exactly what an attacker holding the
-- operator master key -- e.g. from a *different*, unrelated bug -- needs to
-- decrypt) and every other table in the schema, even though no worker code
-- path ever reads almost all of them.
--
-- This script creates a distinct LOGIN role for the worker with SELECT only
-- (never INSERT/UPDATE/DELETE -- the worker's own PersistentStore is a
-- read-only snapshot; every write it needs is relayed to main over IPC, see
-- src/federation_worker/AGENTS.md rule 3), granted table by table, on
-- EXACTLY the tables database::federation_worker_table_allowlist
-- (include/merovingian/database/persistent_store.hpp) names -- no more.
--
-- This is a fail-closed ALLOWLIST, not a "grant everything, then revoke the
-- secrets" denylist: it uses no `ALTER DEFAULT PRIVILEGES` and no
-- `GRANT ... ON ALL TABLES`, so a future migration's new table -- secret or
-- not -- is UNREADABLE by this role until an operator adds a GRANT line here
-- deliberately, in the same change that adds it to
-- federation_worker_table_allowlist. tests/unit/test_worker_db_uri.cpp
-- parses both this file and that array from the source tree and asserts
-- they name the exact same set of tables, so the two cannot drift silently.
--
-- A SEPARATE LOGIN, not SET ROLE onto a restricted role from the same login
-- used elsewhere, is the point: ADR-0062 rejected SET ROLE-based separation
-- for this boundary specifically because a session holding the *login* role
-- that granted a restricted role can always `RESET ROLE` right back to it.
-- Only a distinct login credential the worker process never holds in the
-- first place is a real boundary. The worker never SET ROLEs at all --
-- WorkerEventLoop::run() (federation_worker::apply_worker_database_uri)
-- clears database.runtime_role/migration_role on its own config copy before
-- connecting, so it authenticates with exactly the grants this script gives
-- :fed_worker_role, nothing assumed on top.
--
-- Run this script AFTER provision-roles.sql, against the same database, as a
-- PostgreSQL superuser (or a role with CREATEROLE + ownership of the target
-- database). Replace the placeholders below. Unlike provision-roles.sql's
-- :migration_role/:runtime_role, :fed_worker_role is NOT granted to
-- :login_role -- it is an entirely separate credential with its own
-- password, referenced only from the secret file
-- federation.worker.database_uri_file names (never from database.uri_file,
-- which main alone reads):
--   :db_name          -- the Merovingian database, e.g. merovingian
--   :fed_worker_role  -- e.g. merovingian_fed_worker
--
-- Example (psql):
--   psql -v db_name=merovingian -v fed_worker_role=merovingian_fed_worker \
--        -f packaging/postgresql/provision-federation-worker-role.sql
--   -- then, separately, as the database superuser or fed_worker_role's owner:
--   ALTER ROLE merovingian_fed_worker WITH LOGIN PASSWORD '...';
--
-- Write the resulting connection string (with that password) to the file
-- federation.worker.database_uri_file names, owner-only (0400/0600),
-- readable by the merovingian-server process only -- main reads it once at
-- startup and hands it to each worker shard over an inherited pipe fd; the
-- worker process itself never opens this file (see
-- homeserver::WorkerSupervisor::spawn_and_connect,
-- homeserver::kWorkerDbUriFd).
--
-- federation.worker.allow_shared_database_credentials=true skips all of
-- this and lets the worker share main's login instead -- every startup then
-- logs CRITICAL, since that is exactly the exposure this script closes.

\set ON_ERROR_STOP on

CREATE ROLE :fed_worker_role NOLOGIN;

GRANT USAGE ON SCHEMA public TO :fed_worker_role;

-- Room-scoped tables the worker's local (non-relayed) federation routes
-- read directly: make_join/make_leave/make_knock template generation,
-- backfill, query/directory, state, state_ids, get_missing_events, and
-- space hierarchy. See federation_worker_table_allowlist's own comment in
-- persistent_store.hpp for the file:line trace behind each one.
GRANT SELECT ON rooms TO :fed_worker_role;
GRANT SELECT ON membership TO :fed_worker_role;
GRANT SELECT ON current_state TO :fed_worker_role;
GRANT SELECT ON events TO :fed_worker_role;
GRANT SELECT ON event_edges TO :fed_worker_role;
GRANT SELECT ON event_auth TO :fed_worker_role;
GRANT SELECT ON event_signatures TO :fed_worker_role;
GRANT SELECT ON room_aliases TO :fed_worker_role;

-- server_signing_keys is column-restricted, not table-restricted: the
-- worker's remote-key-cache read/write path (federation::
-- remote_key_cache_probe / remote_key_resolver) legitimately needs this
-- table to cache OTHER servers' public keys, but must never be able to
-- select this server's OWN encrypted signing secret. The worker's loader
-- (src/database/postgresql_store.cpp load_persistent_rows) never includes
-- secret_key in its SELECT list for this profile; this GRANT is the
-- database-level backstop that makes that true even if a future bug widened
-- the C++ query -- PostgreSQL itself refuses a query naming a column this
-- role was never granted.
GRANT SELECT (server_name, key_id, public_key, valid_until_ts) ON server_signing_keys TO :fed_worker_role;

-- Schema bookkeeping: needed for ANY store to open (schema-version check),
-- not gated by TableLoadProfile at all -- see
-- database::open_postgresql_persistent_store's load_schema_state call,
-- which runs before role-specific row hydration.
GRANT SELECT ON schema_migrations TO :fed_worker_role;

-- Deliberately NOT granted, and NOT covered by any ALTER DEFAULT PRIVILEGES
-- or GRANT ... ON ALL TABLES: every other table in the schema, including
-- secret_key on server_signing_keys, users/access_tokens/refresh_tokens/
-- login_tokens/openid_tokens/account_threepids and the rest of
-- migrations/*.sql. A future migration's new table is unreadable by this
-- role by default -- extending access requires adding both a GRANT line
-- here and an entry in federation_worker_table_allowlist, in the same
-- change, which tests/unit/test_worker_db_uri.cpp enforces stay in sync.
