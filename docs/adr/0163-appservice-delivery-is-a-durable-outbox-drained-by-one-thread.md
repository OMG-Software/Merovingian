# Appservice delivery is a durable outbox drained by one thread

* Status: accepted
* Date: 2026-10-17

Technical Story: audit finding R01. After an appservice outage the events sent during it were lost: the
cursor held one pending event, a failed retry skipped the current event, and the next success jumped
`delivered_stream_ordering` past everything in between. Nothing retried when room traffic stopped, and
two requests could race on one cursor.

## Context and Problem Statement

The Application Service API says the homeserver "MUST maintain a queue of transactions to send to the
application service", "SHOULD backoff exponentially" when it cannot be reached, can make the requests
"without blocking other aspects of the homeserver", and "MUST NOT alter (e.g. add more) events they were
going to send within that transaction ID on retries". The previous design kept one pending event per
appservice and delivered synchronously on the request thread that produced the event. How should the
queue be kept, and who sends from it?

## Considered Options

* One row per queued event (`appservice_outbox`), drained by one dedicated thread
* A stream cursor: everything with a stream ordering above `delivered_stream_ordering` is owed
* Keep synchronous delivery on the request thread and make the retry loop smarter
* Batch every owed event into one transaction

## Decision Outcome

Chosen option: an `appservice_outbox` table with one row per `(appservice, stream_ordering)`, written
at event time and drained by one `PeriodicJob` thread, one event per transaction, with in-memory
exponential back-off.

* **Outbox rows, not a stream cursor.** Whether an appservice is interested in an event depends on the
  room's members and aliases at the moment the event is dispatched, and that cannot be recomputed later.
  A cursor would also have to decide which events are "owed" by comparing stream orderings, and that is
  wrong here: stream orderings are allocated before an event commits, and events in different rooms commit
  and dispatch out of order (the room stripes in `ingest_pdu_event`). A threshold check
  (`stream_ordering <= delivered_stream_ordering` means skip) drops a late event with a lower ordering.
  The primary key `(appservice_id, stream_ordering)` is the only dedupe, and `enqueue_appservice_event`
  must never gain an "already delivered" test. `delivered_stream_ordering` is kept, as the maximum
  acknowledged ordering, for information only.
* **The cursor still fixes the transaction.** The drainer writes `pending_txn_id`, the next ID and the
  event's ordering to the cursor before it sends, so a retry in this process or after a restart reuses
  the ID with that event and nothing else. The cursor advance and the row's deletion commit in one
  database transaction (`complete_appservice_delivery`), and memory follows the commit.
* **One drainer thread.** `drain_appservice_queues` is called by exactly one thread, so each appservice
  has at most one transaction in flight and there is no cursor to race on. It takes `runtime.mutex` only
  around reads and writes and releases it around each outbound call. A request only enqueues (no
  network, no lock release) and wakes the thread through `HomeserverRuntime::appservice_delivery_wake`.
  The hook is cleared under `runtime.mutex` before the thread is stopped at shutdown.
* **One event per transaction.** Interest is decided at event time and the contents of a transaction
  must not change once its ID is out, so a transaction is the one event it was created for. Batching
  would have to merge events with different interest decisions, or hold events back until a batch
  filled.
* **Back-off is in memory.** After a failure the appservice waits 1 s, doubling to 5 min; a restart
  forgets it and tries at once, which costs one failed call at most. Persisting it was judged not worth
  a column.

### Positive Consequences

* No event is lost to an outage, and delivery resumes without further room traffic.
* A slow or dead bridge cannot hold a request thread or the runtime lock.
* A transaction ID is never reused for different contents.

### Negative Consequences

* The queue of an appservice that never returns grows without bound: no row is dropped for age. An
  operator removes the registration, or the rows, to stop it.
* Delivery is at-least-once: a crash between the appservice's acknowledgement and the commit re-sends the
  same transaction ID, which the spec allows.
* Throughput per appservice is one transaction per round trip.

## Pros and Cons of the Options

### Stream cursor

* Good, because there is no new table.
* Bad, because it cannot see events that commit below the high-water mark, and it cannot replay an
  interest decision made at event time.

### Synchronous delivery on the request thread, with a smarter retry

* Good, because it needs no thread.
* Bad, because the request waits on the bridge (up to the 30 s outbound timeout) and nothing retries
  when traffic stops; concurrent requests race on one cursor.

### Batching

* Good, because fewer round trips after an outage.
* Bad, because a batch's contents are not immutable while it fills, and the spec forbids altering a
  transaction on retry.

## Links

* Spec: `docs/matrix-v1.19-spec/application-service-api.md`, "Pushing events"
* `include/merovingian/homeserver/appservice_delivery.hpp`
* `migrations/022_appservice_outbox.sql`
* `include/merovingian/homeserver/periodic_job.hpp`

## Notes

* 2026-10-22 (0.12.37): the negative consequence "the queue of an appservice that never returns grows
  without bound" is now bounded by `appservice.max_queued_events`
  ([ADR-0191](0191-cap-queued-events-per-appservice.md)). Ephemeral data rides these transactions but
  is held in memory, not in the outbox
  ([ADR-0190](0190-appservice-ephemeral-data-is-in-memory-bounded-and-best-effort.md)). The decision
  above is unchanged.
