# Rate-cap audit rows for unauthenticated rejections

* Status: accepted
* Date: 2026-09-29

Technical Story: 2026-09-29 security audit, finding AUTH-1 (unauthenticated
requests write unbounded, synchronous audit rows under the global lock) and the
AUTH-1 addendum (`docs/security-audit-report-2026-09-29.md`).

## Context and Problem Statement

Three audit events are triggered by a request from anyone, before any
credential is checked: `access_token.rejected` (an unknown or expired bearer
token), `rate_limit.exceeded` (the limiter refused the request) and
`request.rejected` (refused with 413, 429 or 503 before routing). Each was
written as a durable `audit_log` row on every occurrence, under
`HomeserverRuntime::mutex`. On SQLite that is one connection and one commit per
row. The rows were also appended to two in-memory containers that nothing
trimmed. A client that only sends junk therefore chooses the server's write
rate, its memory growth and its table growth, and a denial (429) added work
instead of shedding it.

The natural question is how to keep an audit trail of attacks without letting
the attacker drive the volume.

## Decision Drivers

* An unauthenticated client must not control how many durable writes, or how
  many bytes of memory, the server spends on it.
* The audit trail must still show that a flood happened and how large it was.
* Authenticated and administrative events (logins, admin actions, room and
  media moderation) must stay one row per occurrence; sampling them would
  destroy the trail operators rely on.

## Considered Options

* Write every rejection, bound only the memory containers.
* Replace rejection rows with counters or metrics only.
* Write rejection rows through a per-kind rate-capped gate that counts what it
  drops and reports the count on the next row it writes.
* Move the audit write off the request thread onto a queue.

## Decision Outcome

Chosen option: "a per-kind rate-capped gate that counts what it drops",
because it bounds durable writes with a small, testable, lock-local structure
and keeps the trail truthful.

* `observability::AuditRateGate` admits at most 10 durable rows per event kind
  per 60-second window. Further events in the window are counted only.
* The first row written for that kind after the window carries
  ` suppressed=<n>` in its `reason`, so no event is silently lost.
* The gated kinds are the fixed set in `audit_event_is_rate_capped`. The gate
  keeps no state for any other string, so its memory is bounded by that set.
* `append_local_audit` applies the gate, so every caller is covered. A suppressed
  event still has its diagnostic log line: one line per request, no audit work.
* The in-memory containers (`LocalDatabase::audit_events`,
  `PersistentStore::audit_log`) are windows over the most recent 1 024 rows. The
  database table is the complete record.
* `actor`, `target` and `reason` are cut to 255 bytes on a UTF-8 boundary, with
  invalid bytes and control characters replaced, at the audit-append layer
  (`database::append_audit_event` and `append_local_audit`).

### Positive Consequences

* A flood costs at most 30 durable rows a minute across the three gated kinds,
  independent of request rate, and a fixed amount of memory.
* The trail records the size of a flood in one `suppressed=` figure.

### Negative Consequences

* Inside a window past its allowance, individual rejected requests are not
  recorded individually in the audit table. Their diagnostic log lines remain,
  and the next row reports the count. An investigator who needs every rejected
  request during a flood uses the logs.
* The suppressed count is delivered on the next row of that kind. If the kind
  never occurs again, or the process stops first, the count is not persisted.
* `GET /_merovingian/admin/audit` reads the in-memory window, so it shows the most
  recent 1 024 rows, not the whole table. Views that must not lose old rows, such
  as the admin safety-report listing, query the table instead
  (`load_audit_events_by_type_prefix`); a view added later that needs history must
  do the same.

## Pros and Cons of the Options

### Write every rejection, bound only the memory containers

* Good, because nothing is dropped.
* Bad, because the synchronous commit per junk request remains, which is the
  finding's main harm.

### Replace rejection rows with counters or metrics only

* Good, because it costs no rows at all.
* Bad, because a low-rate probe (a handful of bad tokens) disappears from the
  audit table, and the trail loses the individual events that matter most when
  an attack is small.

### Per-kind rate-capped gate (chosen)

* Good, because small volumes are recorded in full and large volumes are
  summarised, which is the behaviour an operator wants.
* Bad, because it adds state and a clock dependency to the audit path.

### Move the audit write off the request thread

* Good, because the request no longer waits for the commit.
* Bad, because it does not bound volume, only where the cost lands, and it adds a
  queue whose own growth would need a bound.

## Links

* Related to [ADR-0002](0002-use-an-owner-tracking-mutex-for-the-runtime-lock.md),
  whose global lock the audit write was held under.
