# A delayed event is a stored row that is kept after it is finalised, bounded per user, and deleted with the account

* Status: accepted
* Date: 2026-11-17

## Context and Problem Statement

A delayed event ([ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md))
must survive a restart, because a call's leave that is lost leaves a vanished participant listed in the call, the bug
the feature exists to fix. After it is sent or cancelled, clients still ask about it: the spec answers a repeated
action with 200 or 409, a lookup shows the outcome and any stored error, and the event it became carries
`unsigned.delay_id`. How is it stored, how long is it kept, and what bounds it?

## Decision Outcome

Chosen option: "one table, with finalised rows kept for a bounded time", because it gives the spec's answers and
survives restarts with one mechanism.

* Migration 003 (`migrations/003_delayed_events.sql`, schema version 3, name `delayed_events`) adds the table
  `delayed_events` and the index `idx_delayed_events_user_id` on `(user_id)`, following
  [ADR-0778](0778-the-schema-is-built-from-per-version-tables-and-each-migration-step-from-what-its-version-adds.md)
  exactly as migration 002 did. An earlier version's definitions, `001_initial_schema.sql` and
  `002_oauth_tables.sql` are never edited.
* Every column is `TEXT`, with no NULLs, like every other table: numbers are decimal text, absent values are `''` or
  `0`. The columns are `delay_id` (primary key), `user_id`, `device_id`, `room_id`, `event_type`, `is_state`,
  `state_key`, `content_json`, `txn_id`, `via_appservice`, `delay_ms`, `delayed_since_ms`, `status` (`scheduled`,
  `sent`, `cancelled` or `failed`), `finalised_at_ms`, `event_id` and `error_json`.
* The table is mirrored in memory in `PersistentStore` and hydrated at start-up on both backends. A table class in
  the database module, `DelayedEventTable`, owns the rows and keeps its indexes right by construction; nothing else
  touches the rows. Its indexes are by delay ID; per user, the scheduled count and the finalised rows oldest first;
  scheduled rows ordered by due time (`delayed_since_ms + delay_ms`, then `delay_id`); by (user, device, room, event
  type, transaction ID) for idempotency; by event ID for sent rows; and finalised rows by finalised time. The runtime
  mutex serialises it, so it has no lock of its own.
* The mirror changes only after the transaction commits (one exception, in
  [ADR-0825](0825-a-due-delayed-event-is-sent-by-one-job-through-the-ordinary-send-path-never-early-and-at-least-once.md)).
* A user may hold at most `max_scheduled_per_user` scheduled events. At the cap a new one is refused with
  `429 M_LIMIT_EXCEEDED`; a scheduled event is the user's state and is never evicted.
* Finalised rows are kept for the spec's idempotent answers, for `GET` and for `unsigned.delay_id`. They are bounded
  per user by `max_finalised_per_user` (default 100): when a row is finalised and the user is at the bound, that
  user's oldest finalised rows are deleted in the same transaction. They are bounded in age by a fixed 7 days, pruned
  by the delayed-events job, at most 500 rows per transaction, oldest first.
* A restart of a scheduled event is persisted: it updates `delayed_since_ms`.
* Deactivating an account deletes all of the user's rows, scheduled and finalised, in one transaction, as a step of
  `deactivate_user_account` beside the pusher cleanup. A failure is logged and deactivation continues; the check at
  send time (ADR-0825) is the guarantee.
* Logout and device deletion do not cancel. A delayed event belongs to the user; any of their devices, or an
  application service acting for them, may manage it.
* The federation worker never reads the table. It is classified in the never-reads set of
  `tests/unit/test_worker_table_load_profile.cpp`.

## Pros and Cons of the Options

### Delete the row when it is sent or cancelled (Synapse)

* Bad, because there is then no 200 and 409 distinction, no stored error, and no `unsigned.delay_id`.

### An in-memory queue only

* Bad, because it is lost on restart, which leaves a vanished participant listed in a call.

### Not persisting each restart

Persist only the schedule, not the postponement.

* Bad, because after a server restart the persisted deadline is earlier than the one the client last set, and the
  event would be sent early. The alternative of restarting every timer at start-up never sends for a server restarted
  more often than the delay. The price accepted is one small write per restart, the same as Synapse.

### The spec's example retention (7 days or 1000 per user)

* Bad, because every row is mirrored in memory with its content (up to 65,536 bytes). The count is 100 by default and
  configurable; the age is the spec's 7 days.

### Cancelling on logout or device deletion

* Bad, because a call's leave must still fire after its device is gone.

### `INTEGER` or nullable columns

* Bad, because every table in this schema stores numbers as text and has no NULLs.

## Consequences

* A new reader goes through the table class's indexes and never scans the table.
* The worst case held for one user is `max_scheduled_per_user` plus `max_finalised_per_user` rows of at most 65,536
  bytes of content.
* The federation worker does not read the table; a change that makes it read the table must change its
  classification deliberately.
* A new code path that deletes an account's data must delete these rows too.

## Links

* Related: [ADR-0778](0778-the-schema-is-built-from-per-version-tables-and-each-migration-step-from-what-its-version-adds.md)
* Related: [ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md)
* Related: [ADR-0826](0826-delayed-events-are-on-by-default-with-a-maximum-delay-per-user-caps-and-per-user-rate-limits.md)
