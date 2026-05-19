# PostgreSQL libpq dependency review

This note records the dependency review for adding PostgreSQL support through
`libpq`, the PostgreSQL project-owned C client library.

## Decision

`libpq` is accepted as the PostgreSQL client dependency for Merovingian. It is
wrapped inside the database module and must not leak `PGconn`, `PGresult`, or
other libpq-specific types into homeserver services.

## Why it is needed

PostgreSQL is the intended production database backend. Speaking the PostgreSQL
wire protocol directly would be high-risk, unauditable project code. `libpq` is
the native PostgreSQL client API, is packaged by supported Linux and BSD
distributions, and gives the project a stable interface for connection
management, parameterized execution, and PostgreSQL error reporting.

## Security boundary

- Connection strings are accepted only in explicit PostgreSQL URI or libpq
  key/value form.
- Connection summaries redact passwords before they can be logged or surfaced in
  diagnostics.
- `PGconn` ownership is RAII-managed with `PQfinish`.
- `PGresult` ownership is RAII-managed with `PQclear`.
- Statement execution uses `PQexecParams` so parameter values stay separate from
  SQL command text.
- Existing project statement-name, SQL-shape, and placeholder validation still
  runs before libpq execution.
- Runtime startup uses PostgreSQL only when a URI file is explicitly present;
  otherwise existing in-memory test flows remain isolated from ambient
  databases.
- Runtime startup requires `database.role=runtime`; offline migration planning
  requires `database.role=migration`.

## Maintenance and platform posture

`libpq` is resolved from the operating-system PostgreSQL client package and
linked dynamically. The top-level Meson dependency sets `allow_fallback: false`,
so clean builds must provide `libpq.pc` through the host package manager even
when the wrapper scripts use Meson's `forcefallback` mode for other
dependencies.

Supported development paths install the OS development package explicitly:
Debian-family hosts use `libpq-dev`, Fedora-family hosts use `libpq-devel`,
FreeBSD uses `postgresql17-client`, OpenBSD uses `postgresql-client`, and
NetBSD/pkgsrc uses `postgresql17-client`.

## Current limitations

- Live integration tests against a temporary PostgreSQL server are gated by
  `MEROVINGIAN_TEST_POSTGRESQL_URI`.
- Separate PostgreSQL users/grants for runtime and migration roles are not yet
  enforced by database permissions.

## Source references

- PostgreSQL libpq connection control documentation.
- PostgreSQL libpq command execution documentation.
