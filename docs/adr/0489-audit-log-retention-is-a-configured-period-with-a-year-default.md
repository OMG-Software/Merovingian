# Audit log retention is a configured period, a year by default, and a purge is itself audited

* Status: accepted
* Date: 2026-11-04

Technical Story: November analysis G7.

## Context and Problem Statement

`audit_log` grew without bound. `docs/observability-audit.md` listed "retention and export policy for production audit
archives" as deliberately not included, so no document fixes a period. An audit log's retention is a security
property: a default that quietly dropped evidence would be worse than the growth.

## Decision Outcome

`security.audit_log_retention_days` (reloadable). `0` keeps every row for ever. Otherwise `30..3650`; anything else is
refused when the configuration is parsed (a retention under a month would let an attacker wait out the evidence). The
default is 365.

A default that deletes is chosen over a default that keeps because an operator who never reads this key still gets a
bounded table, and the deletion is not silent: every sweep that deletes writes one `audit.retention.purged` row
(written after the deletion, so it is never deleted by it) saying the cutoff, the retention in days and the number of
batches. The operator who needs the evidence for longer sets a longer period or `0`.

To age rows, `audit_log` gains `created_at_ms TEXT NOT NULL DEFAULT '0'` (Unix ms, stamped by `append_audit_event`).
Rows stamped `0` are never deleted. The two inserts name their columns.

Deletion is bounded inside the statement (`DELETE ... WHERE rowid|ctid IN (SELECT ... LIMIT 500)`), because `audit_log`
has no key. The sweep asks "is any row older than the cutoff" on a connection of its own before each batch, since the
write path reports no row count; it runs at most 20 batches per sweep and takes `runtime.mutex` only for one batch.

PostgreSQL used `ctid` as the insertion order of an append-only table. Deleting rows breaks that (freed space is
reused), so hydration and the prefix query order by `created_at_ms`, then `ctid` within one millisecond.

## Consequences

* The in-memory `LocalDatabase::audit_events` window has no timestamp and can show rows older than the retention until
  they leave the window; the durable table and `PersistentStore::audit_log` are trimmed.
* The existence probe scans `audit_log` when nothing is old enough (no index: the column is TEXT and the comparison
  casts, like every other numeric column here). That is once an hour, off the lock.
* Do not change the default to a value that deletes silently, and do not drop the purge row.
