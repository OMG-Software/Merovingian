# A failed sync stream watermark write is logged and healed by the next write

* Status: accepted
* Date: 2026-11-07

Technical Story: analysis finding S6, `allocate_sync_stream_id` discarded the result of the watermark write

## Context and Problem Statement

`allocate_sync_stream_id` raises the counter and writes the new value to the `sync_stream_watermark` row, so a
restart cannot hand out a position again (ADR-0315). Ephemeral surfaces (typing, receipts) leave no durable row,
so the watermark is the only record of their positions. The write's result was dropped with `std::ignore`, so a
failure left no trace. If the server restarted before any later write succeeded, the counter would come back lower
and could issue a position a client holds in a since token again; a row at or below a since token is not
delivered, and a to-device row there is deleted as acknowledged.

## Considered Options

* Log the failure at error level and issue the id
* Fail the allocation with `std::overflow_error`, leaving the counter advanced
* Change the return type to `std::expected` and handle it in each of the 25 callers

## Decision Outcome

Chosen option: "Log the failure at error level and issue the id".

Every allocation writes the counter's current value, not an increment, so the next write that succeeds records the
counter past every id issued before it, the failed one included. Only a restart before any write succeeds can lose
the id, and then the database is failing the event and membership writes the ids belong to as well. The log line
`sync_stream.watermark_persist_failed` carries the position.

Throwing was tried and rejected. Most callers allocate after their own commit: `create_room`, local and federated
`join_room`, `leave_room`, `knock_room`, the shared membership path behind invite, kick and ban, and the resident's
`send_join`/`send_leave`/`send_knock` acceptor. A throw there skips the sync notification and push, answers a 500
for a room that was created (a retrying client creates a second one), drops the PDUs buffered during a federated
join, and on the federation paths escapes to the thread pool with no answer to the peer. ADR-0315 can throw at the
ceiling because the ceiling is never reached in practice and the writes a position must follow stop a margin below it;
a database error has no such margin. `std::expected` through 25 callers was rejected for the same reason ADR-0315
rejected it.

`restore_sync_stream_id` logs a failed write too (`sync_stream.watermark_restore_failed`): the counter is already
at the highest durable row, and the next restart derives the same floor.

### Negative Consequences

* A restart after a failed write and before any successful one can reissue the ids issued in between. A
  persistently failing database fails the request writes first.
