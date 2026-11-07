# A sync stream id whose watermark write fails is not issued

* Status: accepted
* Date: 2026-11-07

Technical Story: analysis finding S6, `allocate_sync_stream_id` discarded the result of the watermark write

## Context and Problem Statement

`allocate_sync_stream_id` raises the counter and writes the new value to the `sync_stream_watermark` row, so a
restart cannot hand out a position again (ADR-0315). Ephemeral surfaces (typing, receipts) leave no durable row,
so the watermark is the only record of their positions. The write's result was dropped with `std::ignore`: a
failed write still issued the id, a client could hold it in a since token, and after a restart the counter would
come back lower and issue it again. A row at or below a client's since token is not delivered, and a to-device
row there is deleted as acknowledged.

## Considered Options

* Log at error level, mark the store unhealthy, and issue the id anyway
* Fail the allocation with `std::overflow_error`, leaving the counter advanced
* Fail the allocation and roll the counter back
* Change the return type to `std::expected` and handle it in each of the 25 callers

## Decision Outcome

Chosen option: "Fail the allocation with `std::overflow_error`, leaving the counter advanced".

Issuing an id the store could not record is the defect, so the first option keeps it. Rolling back is wrong
because a commit can succeed while reporting failure; the watermark may then already hold the id, and issuing it
later is the reuse the watermark prevents. Leaving the counter advanced burns one position, which costs nothing:
positions need only increase.

`std::overflow_error` is what ADR-0315 already throws at the ceiling, for the same reason (returning an error
through 25 callers was rejected there), and the callers that must degrade already catch it as "no position
available". The log line `sync_stream.watermark_persist_failed` carries the position.

`restore_sync_stream_id` also checks its write, but only logs at error level: the counter is already at the
highest durable row, and the next restart derives the same floor, so nothing can be reissued.

### Negative Consequences

* A caller that does not catch `std::overflow_error` fails the whole request when the database is failing; it
  would have failed on its own write at the same moment.
