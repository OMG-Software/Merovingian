# Each outbound destination holds a bounded share of the dispatch queue, and every transaction has its own ID

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `fed.outbound-fanout-unbounded-destinations-queue-poison`

## Context and Problem Statement

Every outbound federation transaction goes through one `DispatchWorker` queue, bounded at
`outbound_queue_capacity` (4096). A transaction for a destination whose circuit is open is put back
on the queue without counting a retry, so a dead or hostile peer that shares a room keeps its
transactions queued indefinitely. Enough of them filled the queue, and from then on every other
peer's transactions were refused. The room-event fan-out discarded `enqueue`'s result, so nothing
recorded the loss.

Two further defects were found while fixing it. Both fan-outs (room events, and EDUs) gave every
destination the same transaction ID, and that ID is the primary key of the durable
`federation_transactions` row. So a fan-out kept one durable row (the last destination's), and the
first successful delivery deleted the row the others' replay depended on.

## Decision Drivers

* One peer must not be able to take the delivery capacity every other peer depends on.
* A refused transaction must be visible to operators, not discarded silently.
* `enqueue` runs under `runtime.mutex` during fan-out, so its admission check must be O(1).
* The spec lets a server that missed a PDU recover it (`prev_events`, `/get_missing_events`).

## Considered Options

* Bound each destination's share of the queue in `DispatchWorker::enqueue`
* Skip destinations in backoff when the fan-out builds its destination list
* Persist refused transactions for later replay
* Leave the queue shared and only log refusals

## Decision Outcome

Chosen option: "bound each destination's share of the queue in `DispatchWorker::enqueue`". A
destination may hold `DispatchWorkerConfig::max_pending_per_destination` queued transactions;
zero derives it as `max(16, max_queue_depth / 16)`, which is 256 for the default queue. The count is
kept per destination under the worker's mutex and changed only by `push_queue_locked` and
`note_dequeued_locked`, so the check costs one hash lookup. Past the share, or past the whole
queue, `enqueue` returns false and counts the refusal in `DispatchWorkerSummary::rejected`, which
is exported as `merovingian_federation_outbound_rejected_total`. The room-event fan-out logs the
refused destinations at warning level (`room.event.dispatch_refused`).

Every destination gets its own transaction ID, in both fan-outs.

### Positive Consequences

* A dead peer takes at most a sixteenth of the queue; healthy peers keep delivering.
* Refusals are counted and logged.
* Each queued transaction has its own durable row, so a restart replays every destination's.

### Negative Consequences

* A peer past its share misses those pushed events until it fetches them itself.
* Sixteen or more dead destinations can still fill the queue together. Each is bounded; the total
  is still the queue size.
* The in-memory destination list (`destinations_`) is still not evicted; it grows with the number
  of distinct peers ever contacted.

## Pros and Cons of the Options

### Skip destinations in backoff at fan-out

* Bad, because `destinations_` belongs to the worker thread and is read there without the mutex;
  reading it from the request path is a data race.
* Bad, because it drops events for a peer that failed once and is about to recover.

### Persist refused transactions for later replay

* Bad, because it moves the unbounded growth from memory to the database.

### Log refusals only

* Bad, because one peer can still starve the rest.

## Links

* Related: [ADR-0165](0165-retain-unresolved-federation-pdus-and-retry-them.md) (deferred PDUs are retained on the receiving side)
