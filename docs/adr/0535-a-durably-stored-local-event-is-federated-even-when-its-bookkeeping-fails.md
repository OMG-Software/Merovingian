# A durably stored local event is federated even when its bookkeeping fails

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

`persist_composed_event` returned `false` when `finish_local_membership` (the live roster and device-list rows)
failed after `store_local_event` had already committed the event. Callers then answered 500 and skipped
federation and the sync notification for an event that exists durably.

## Considered Options

* Keep one `bool` and treat a bookkeeping failure as success.
* Return `PersistOutcome` (`stored`, `stored_bookkeeping_failed`, `not_stored`).
* Roll the event back when the bookkeeping fails.

## Decision Outcome

Chosen option: `PersistOutcome`. Only `not_stored` is an error to the client. `stored_bookkeeping_failed` is logged
(`event.persist.failed`, with the event ID) and the caller federates, notifies and answers success. A bare `bool`
hides which side of the commit failed; rollback is impossible, since the event is already committed and, for a
local event, possibly seen by readers (ADR-0228: no write after the commit may be one a 500 could leave behind).
New callers of `persist_composed_event` compare against `PersistOutcome::not_stored`.
