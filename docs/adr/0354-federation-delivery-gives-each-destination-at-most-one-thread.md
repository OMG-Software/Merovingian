# Federation delivery gives each destination at most one thread

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-20. Extends ADR-0177.

## Context and Problem Statement

ADR-0177 bounds how much of the outbound queue one peer may hold, on the driver that "one peer must not be able to take the
delivery capacity every other peer depends on". It did not bound how long a peer may hold the worker. All outbound federation
ran on one thread, each attempt could block for up to 30 s of discovery and 60 s of request, and a `2xx` reset the
destination's failure count however long it took. A peer that joined a public room and answered every `/send` after about 55 s
never opened its circuit, and a healthy peer's transaction waited behind up to 256 of its own: about four hours.

The spec also says of `PUT /send/{txnId}`: "The sending server must wait and retry for a 200 OK response before sending a
transaction with a different txnId to the receiving server." A failed transaction went to the back of the queue, so a later
transaction could overtake it.

## Considered Options

* A small pool of threads, one transaction in flight per destination, and a slow success counted against the destination
* One thread per destination
* A pool with no limit per destination
* Keep one thread, with a shorter deadline

## Decision Outcome

Chosen: the pool. `security.federation.outbound_delivery_threads` threads (default 4, 1..64, restart required) deliver from the
one queue.

* **A destination has at most one transaction in flight, and only its oldest can be taken.** A retried transaction returns to
  the front of the queue. A later transaction for the same destination waits while the older one is in backoff, as the spec
  requires, without occupying a thread. Other destinations are unaffected.
* **An attempt has a 30 s deadline**, and discovery runs under its own budget of at most 10 s.
* **A success that took more than 10 s, discovery included, counts against the destination.** The transaction is delivered,
  and `consecutive_failures` grows along the ordinary backoff curve (2 s doubling to 5 min). A success within the limit resets
  it, as before.
* **The circuit is checked before discovery.** A destination in backoff takes no thread for it.
* **A shutdown drains for at most 30 s.** What is not reached stays durable and is replayed on the next start. The drain's
  due time and deadline are shared by all threads, so a thread finishing a long attempt does not retry what another failed
  during the drain (ADR-0309).

Destination state is copied out under the worker's mutex for an attempt and put back after. A reference into `destinations_`
held across a network call, which was harmless with one thread, would dangle as soon as another thread added a destination.

### Positive Consequences

* A stalled or slow peer occupies at most one thread, and only as often as its backoff allows.
* Transactions to a destination are attempted in order, which the single thread did not do either.
* Shutdown ends within the drain budget plus one attempt.

### Negative Consequences

* An attacker controlling many server names can still occupy several threads. Each name must be joined to a room with local
  activity, and each holds a thread for at most about 40 s per backoff period, reaching 5 min after a few slow answers. Holding
  all of the default 4 threads continuously takes tens of names.
* An honest peer that is slower than 10 s is throttled, down to one transaction per 5 min if it stays so, and transactions past
  its queue share are refused. It recovers them through `prev_events` and `/get_missing_events`, and the first fast answer
  resets the backoff.
* An honest request taking over 30 s now fails and is retried. The receiver answers a repeated `txnId` from its record.
* A transaction that keeps failing blocks later ones to its destination until `outbound_max_retries` drops it. The destination's
  circuit would have held them back during that time in any case.
* The 10 s budget covers the `.well-known` fetch. A server whose `.well-known` takes longer is delivered to as if it had none,
  and the attempt is expected to fail until a cached answer exists.
* The scan for the next ready transaction is linear in the queue, under the worker's mutex (not `runtime.mutex`), bounded by
  `outbound_queue_capacity`.

## Pros and Cons of the Options

### One thread per destination

Isolates peers completely, but gives a remote party the power to create threads in this process by being a destination.

### A pool with no limit per destination

One slow peer with a backlog takes every thread within a minute, and the spec forbids a second `txnId` before the first is
answered.

### Keep one thread, with a shorter deadline

Lowers the stall from four hours to two and leaves the defect: every peer still waits for the slowest.
