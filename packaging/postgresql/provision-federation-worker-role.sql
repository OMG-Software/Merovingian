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
-- decrypt) and every other credential-bearing table, even though no worker
-- code path ever reads them (see database::table_load_profile_includes,
-- include/merovingian/database/persistent_store.hpp).
--
-- This script creates a distinct LOGIN role for the worker with SELECT only
-- (never INSERT/UPDATE/DELETE -- the worker's own PersistentStore is a
-- read-only snapshot; every write it needs is relayed to main over IPC, see
-- src/federation_worker/AGENTS.md rule 2) on every table except the ones
-- database::table_load_profile_includes excludes for
-- TableLoadProfile::federation_worker:
--   server_signing_keys, users, access_tokens, refresh_tokens,
--   login_tokens, openid_tokens, account_threepids
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
-- database). Replace the placeholders below -- :login_role and
-- :migration_role must be the exact same values passed to provision-roles.sql,
-- since the default-privilege grants below are keyed on those two roles as
-- creators of the tables migrations add. Unlike provision-roles.sql's
-- :migration_role/:runtime_role, :fed_worker_role is NOT granted to
-- :login_role -- it is an entirely separate credential with its own
-- password, referenced only from the secret file
-- federation.worker.database_uri_file names (never from database.uri_file,
-- which main alone reads):
--   :db_name          -- the Merovingian database, e.g. merovingian
--   :login_role       -- same value passed to provision-roles.sql
--   :migration_role   -- same value passed to provision-roles.sql
--   :fed_worker_role  -- e.g. merovingian_fed_worker
--
-- Example (psql):
--   psql -v db_name=merovingian -v login_role=merovingian \
--        -v migration_role=merovingian_migration \
--        -v fed_worker_role=merovingian_fed_worker \
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

-- Present and future tables: ALTER DEFAULT PRIVILEGES covers every table a
-- later migration creates under either role that can currently create
-- schema objects, the same two-grantor pattern provision-roles.sql uses for
-- :runtime_role and for the same reason -- naming only one silently leaves
-- the other's tables unreadable by :fed_worker_role.
ALTER DEFAULT PRIVILEGES FOR ROLE :migration_role IN SCHEMA public
  GRANT SELECT ON TABLES TO :fed_worker_role;
ALTER DEFAULT PRIVILEGES FOR ROLE :login_role IN SCHEMA public
  GRANT SELECT ON TABLES TO :fed_worker_role;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO :fed_worker_role;

-- Remove SELECT on the credential-bearing tables the worker never reads --
-- see database::table_load_profile_includes, the C++ predicate this list
-- must stay in sync with. A REVOKE after the blanket GRANT above (rather
-- than hand-listing every included table) means a future migration's new,
-- non-secret table is automatically readable by :fed_worker_role without
-- touching this script; only a new SECRET table requires adding a REVOKE
-- line here AND excluding it in table_load_profile_includes.
REVOKE SELECT ON server_signing_keys FROM :fed_worker_role;
REVOKE SELECT ON users FROM :fed_worker_role;
REVOKE SELECT ON access_tokens FROM :fed_worker_role;
REVOKE SELECT ON refresh_tokens FROM :fed_worker_role;
REVOKE SELECT ON login_tokens FROM :fed_worker_role;
REVOKE SELECT ON openid_tokens FROM :fed_worker_role;
REVOKE SELECT ON account_threepids FROM :fed_worker_role;

-- The worker never opens a LOGIN session under this role name directly in
-- this script -- set the password and LOGIN attribute as a separate,
-- deliberate step (see the example above) so the generated connection
-- string is produced and stored exactly once, by whoever runs that step.
