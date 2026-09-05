-- SPDX-FileCopyrightText: 2026 James Chapman
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- PostgreSQL role provisioning for a production Merovingian deployment.
--
-- Merovingian's schema migrations (migrations/*.sql, applied automatically at
-- server startup — see migrations/AGENTS.md and docs/database-persistence.md)
-- need DDL privileges (CREATE TABLE, ALTER TABLE, ...). Day-to-day request
-- handling needs only DML (SELECT/INSERT/UPDATE/DELETE). Running both through
-- one PostgreSQL login that always carries DDL rights means a request-path
-- bug (SQL injection, a compromised dependency, an over-broad query) can
-- reach schema-mutation privileges it never needs. This script provisions
-- two roles so the two privilege levels can be kept apart, and is the same
-- pattern proven in CI — see .github/workflows/postgres-integration.yml,
-- whose "Provision migration and runtime roles" step runs the equivalent SQL
-- against a real ephemeral PostgreSQL service container, and
-- tests/integration/test_postgresql_persistence_flow.cpp, whose
-- "PostgreSQL role enforcement" scenarios prove a session that has SET ROLE
-- to the runtime role cannot execute DDL.
--
-- Replace the four placeholders below before running this script as a
-- PostgreSQL superuser (or a role with CREATEROLE + ownership of the target
-- database):
--   :db_name          -- the Merovingian database, e.g. merovingian
--   :login_role       -- the role in database.uri_file's connection string,
--                        e.g. merovingian
--   :migration_role   -- e.g. merovingian_migration
--   :runtime_role      -- e.g. merovingian_runtime
--
-- Example (psql):
--   psql -v db_name=merovingian -v login_role=merovingian \
--        -v migration_role=merovingian_migration \
--        -v runtime_role=merovingian_runtime \
--        -f packaging/postgresql/provision-roles.sql
--
-- Since 0.12.5 merovingian-server assumes both roles itself: any pending
-- migration is applied after SET ROLE :migration_role, the session is then
-- reset, and request handling runs after SET ROLE :runtime_role. Neither the
-- migration nor the request path executes as the login role. If :migration_role
-- cannot be assumed, startup fails rather than falling back to the login role.
--
-- UPGRADING AN EXISTING DATABASE. Before 0.12.5 the schema objects were created
-- by, and are therefore owned by, :login_role. ALTER TABLE is permitted only to
-- an object's owner, so the next migration would fail under :migration_role
-- until ownership moves across. The transfer at the end of this script does
-- that; it is a no-op on a fresh install, where the migration role owns what it
-- creates from the start.
--
-- Deliberately NOT `REASSIGN OWNED BY :login_role TO :migration_role`. That
-- command operates on everything the role owns across the whole database,
-- including objects the system pins -- so when :login_role is the cluster
-- bootstrap superuser (which is what the official postgres container produces,
-- and what an operator reusing the `postgres` role has) it fails outright with
--
--   ERROR: cannot reassign ownership of objects owned by role <role>
--          because they are required by the database system
--
-- The scoped transfer below touches only the tables and sequences in `public`
-- that :login_role actually owns, which is exactly the Merovingian schema.
--
-- Startup logs `store.rejected reason="migration failed as the configured
-- migration role; ... see the ownership transfer step"` if this was missed.

\set ON_ERROR_STOP on

-- PostgreSQL <= 14 leaves CREATE on schema public granted to PUBLIC by
-- default, which would let :runtime_role execute DDL and defeat the whole
-- point of the split. PostgreSQL 15+ ships without this grant, so the revoke
-- is a no-op there.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE ROLE :migration_role NOLOGIN;
CREATE ROLE :runtime_role NOLOGIN;

GRANT :migration_role TO :login_role;
GRANT :runtime_role TO :login_role;

GRANT CREATE, USAGE ON SCHEMA public TO :migration_role;
GRANT USAGE ON SCHEMA public TO :runtime_role;

-- Tables and sequences a migration creates inherit these default privileges
-- automatically, so a new migration's tables are usable by :runtime_role
-- without a manual GRANT per migration.
--
-- Both grantors are declared. FOR ROLE :migration_role covers everything
-- created since 0.12.5, when migrations began running under that role; FOR ROLE
-- :login_role covers objects created by an older server, and by the bootstrap
-- path a single-role deployment still uses. ALTER DEFAULT PRIVILEGES is keyed
-- on the creating role, so naming only one of them silently leaves the other's
-- tables unreadable by :runtime_role.
ALTER DEFAULT PRIVILEGES FOR ROLE :migration_role IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :runtime_role;
ALTER DEFAULT PRIVILEGES FOR ROLE :migration_role IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :runtime_role;
ALTER DEFAULT PRIVILEGES FOR ROLE :login_role IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :runtime_role;
ALTER DEFAULT PRIVILEGES FOR ROLE :login_role IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :runtime_role;

-- Existing objects, for a database that already has a schema. Harmless on a
-- fresh database, where these match nothing.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO :runtime_role;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO :runtime_role;

-- Transfer ownership of any pre-0.12.5 schema objects to :migration_role, so
-- the next migration can ALTER them. \gexec runs each generated statement;
-- selecting nothing (a fresh install, or an already-migrated database) runs
-- nothing, which is what makes this safe to re-run.
SELECT format('ALTER TABLE public.%I OWNER TO %I', tablename, :'migration_role')
  FROM pg_tables
 WHERE schemaname = 'public' AND tableowner = :'login_role'
\gexec

SELECT format('ALTER SEQUENCE public.%I OWNER TO %I', sequencename, :'migration_role')
  FROM pg_sequences
 WHERE schemaname = 'public' AND sequenceowner = :'login_role'
\gexec

-- Stricter alternative, for a deployment that does not want the login role to
-- be a member of :migration_role at all: skip the "GRANT :migration_role TO
-- :login_role" line and the CREATE/USAGE grant to :migration_role above, leave
-- database.migration_role unset, and apply schema migrations out-of-band as a
-- separate, more privileged role before pointing merovingian-server at the
-- restricted login. More operational overhead per upgrade, and it means the
-- server can never migrate itself — but the login role then has no path to DDL
-- even transiently.
