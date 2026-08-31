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
-- KNOWN GAP (tracked in docs/todos/production-milestone.md and
-- docs/todos/capability-gaps.md): this script provisions the roles and
-- their grants, matching what CI already proves works, but merovingian-server
-- and merovingian-db-migrate do not yet SET ROLE to :migration_role /
-- :runtime_role themselves at startup — the live connection pool currently
-- always runs as the login role (database.uri_file's credentials) for both
-- schema migration and runtime traffic. Provisioning these roles today is a
-- correctness precondition for that future wiring, and lets an operator who
-- wants defence in depth now grant the login role only :runtime_role's
-- privileges (see the operator-driven alternative below) at the cost of
-- running the offline `merovingian-db-migrate --plan` output's DDL by hand
-- (or as the :migration_role member) before each upgrade.

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

-- Tables and sequences created while the login role is (or has been) a
-- member of :migration_role inherit these default privileges automatically,
-- so a fresh migration's new tables are usable by :runtime_role without a
-- manual GRANT per migration.
ALTER DEFAULT PRIVILEGES FOR ROLE :login_role IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO :runtime_role;
ALTER DEFAULT PRIVILEGES FOR ROLE :login_role IN SCHEMA public
  GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO :runtime_role;

-- Operator-driven alternative available today, without waiting on the
-- SET ROLE wiring above: grant the LOGIN role itself only :runtime_role's
-- privileges (skip the "GRANT :migration_role TO :login_role" line and the
-- CREATE/USAGE grant to :migration_role above), and apply schema migrations
-- out-of-band as a separate, more privileged role before pointing
-- merovingian-server at the restricted login. This is more operational
-- overhead per upgrade but is fully enforced by PostgreSQL today.
