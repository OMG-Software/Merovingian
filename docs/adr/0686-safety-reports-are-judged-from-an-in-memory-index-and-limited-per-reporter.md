# Safety reports are judged from an in-memory index and limited per reporter

* Status: accepted
* Date: 2026-11-12

Technical Story: security audit run-3, finding C26.

## Context and Problem Statement

Every report is a durable `trust_safety.*.accept_report` audit row, and each report first loaded the newest 1000 rows of
its type from `audit_log` under `runtime.mutex` to find a repeat by the same reporter. `audit_log` has no index, so on
PostgreSQL that read sorts the whole table. Any local user could report any syntactically valid remote user ID, each a new
row, because the 20 a minute that `trust_safety::route()` declares was never read by anything: the generic 600 a minute
applied. One user could fill the administrators' listing (the newest 1000 rows) with their own rows and grow the table every
later report scans.

## Considered Options

* An in-memory `SafetyReportIndex` of the report window plus per-reporter times, filled once at start-up from the stored rows.
* A table of reports with a unique key (reporter, target), or an index on `(event_type, created_at_ms)`: a schema migration.
* Apply the rate limit only.

## Decision Outcome

Chosen option: the in-memory index, a per-user 20 a minute limit on both report routes (entries in `builtin_per_user`,
beside `get_token` and `preview_url`), and a share of 100 distinct reports per reporter per day, answered `429
M_LIMIT_EXCEEDED`. A repeat inside the window the listing shows is still acknowledged with 200 and no row.

The index is a derived copy of rows the table already holds and is rebuilt from them at start, so a restart loses nothing and
no migration is needed. A table with a unique key was rejected: the frozen v1 schema would need a migration, the listing
still reads `audit_log`, and the unique key does not bound a reporter's share.

The administrators' listing (`GET /admin/safety/reports`) still reads the newest `max_safety_report_rows` audit rows once per
call. It is not on a low-trust path (administrator token, the `admin` tier is 30 a minute), and one reporter can no longer fill
it: 100 reports a day each. Residual: many accounts, each at its share, can still fill the 1000-row listing; their rows are
bounded by the number of accounts times 100 a day, and genuine reports stay in the durable table.

## Links

* Refines [ADR-0482](0482-a-user-report-about-an-unknown-local-user-is-404-and-about-a-remote-user-is-accepted.md)
