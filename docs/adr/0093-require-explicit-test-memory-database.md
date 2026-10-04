# Require explicit selection of the test-only memory database

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

The configured production default is PostgreSQL. When its URI file was absent
or empty, startup silently opened the in-memory store instead. The server could
then appear healthy while acknowledging writes that disappeared at restart.
Tests that intentionally do not exercise persistence still need a cheap
process-local store, but that convenience must not become a production
fallback.

## Considered Options

* Fail PostgreSQL startup when credentials cannot be read and expose memory only through programmatic test setup.
* Default test and production configurations to SQLite.
* Keep the implicit memory fallback when the PostgreSQL URI is unavailable.

## Decision Outcome

Treat an unavailable or empty PostgreSQL URI as a startup failure. Add a
programmatic `DatabaseBackend::memory` branch for test fixtures, but do not
accept `memory` in the config parser. Test helpers choose it explicitly;
SQLite and PostgreSQL remain the only deployable backend values.

Defaulting tests to SQLite was rejected because most service tests do not
exercise persistence and would gain filesystem side effects and cleanup
requirements. Retaining the fallback was rejected because it turns a missing
production secret into silent loss of durable writes.

### Positive Consequences

* A deployment cannot start successfully against an unintended ephemeral store
  when PostgreSQL credentials disappear.
* Tests retain a pure, explicit backend choice without opening files or a
  database process.
* Configuration has one unambiguous source of backend selection.

### Negative Consequences

* Tests that use runtime fixtures without exercising persistence must opt into
  the memory backend explicitly.
* Existing deployments that accidentally depended on the fallback now fail
  startup and must configure PostgreSQL or deliberately choose SQLite.

## Links

* [DB-3 audit finding](../security-audit-report-2026-09-29.md#db-3--the-postgresql-backend-silently-runs-on-an-in-memory-store-when-databaseuri_file-is-missing-or-empty)
* [Database persistence](../database-persistence.md)
