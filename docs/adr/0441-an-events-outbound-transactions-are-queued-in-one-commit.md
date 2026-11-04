# An event's outbound transactions are queued in one commit

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-04

Technical Story: Performance defect P5, one commit per remote server per event.

## Context and Problem Statement

`queue_event_to_room_servers` enqueued one `OutboundTransaction` per remote server, and each `enqueue` committed a
`federation_transactions` row (SQLite runs `synchronous=FULL`, so each commit is a sync) and then searched the
in-memory transaction vector linearly. The server list was built with a linear search per member.

## Decision Outcome

* `DispatchWorker::enqueue_batch` admits an event's transactions with the same checks as `enqueue` (shape,
  operator policy, shutdown, queue depth, per-destination share, ADR-0177), counting the batch's own earlier
  members, then writes every admitted row with `store_federation_transactions` in one transaction before any
  is pushed to the queue. A row is therefore on disk before it can be sent, as before.
* A failed commit refuses every admitted transaction of the batch: none is queued or stored, each is logged as
  `enqueue.rejected` ("failed to persist transaction"), and the caller reports them in `room.event.dispatch_refused`
  as it did. Nothing is half queued. Transactions refused by a bound or by policy are still refused alone.
* `federation_transactions` has a position index by transaction ID, trusted only while in step with the vector
  (the ADR-0344 pattern). `delete_federation_transaction` keeps the vector's order and rebuilds the index.
* `enqueue` is `enqueue_batch` of one. Server names are collected through a set.

## Considered Options

* Commit per destination as before. Rejected: it is the cost being removed.
* Let a failed commit refuse only the rows after the failure. Rejected: a single transaction cannot partly
  commit, and re-trying rows one at a time would hide the failure behind the slow path.

## Links

* Refines [ADR-0177](0177-each-outbound-destination-holds-a-bounded-share-of-the-dispatch-queue.md)
* Related to [ADR-0440](0440-push-recipients-read-their-own-rows-and-share-one-notification-commit.md)
