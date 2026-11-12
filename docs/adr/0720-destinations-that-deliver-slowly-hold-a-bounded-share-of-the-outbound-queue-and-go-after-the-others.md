# Destinations that deliver slowly hold a bounded share of the outbound queue and go after the others

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C20 (resource-exhaustion.dispatch-worker.sub-threshold-slow-success-keeps-destination-live-and-holds-queue)

## Context and Problem Statement

ADR-0354 makes a success that took longer than `slow_attempt_ms` (10 s) count as a failure, and ADR-0621 keeps half of the
outbound queue for destinations that are not failing, deciding "failing" by `consecutive_failures`. A peer that answers
every `PUT /send` with 2xx after 9.5 s never fails and never counts as slow. Its backlog grows to its destination share,
sixteen such names hold all 4096 slots, and four of them keep the four default delivery threads busy. The existing
controls (the failing share, the 24 h age limit, the shed) all key on failing, so none applies.

## Decision Drivers

* A destination that delivers must not lose transactions (ADR-0177: delivery is in order, and what is queued is owed).
* One-in-flight-per-destination and oldest-first per destination (ADR-0354, the spec's send rule) must hold.
* The attacker picks its side of any single time threshold.

## Considered Options

* Count a quarter-limit answer as a failure, so it is shed and aged out like a dead destination
* Lower `slow_attempt_ms`
* Mark a destination slow after an answer over a quarter of `slow_attempt_ms`; refuse its new rows past a shared share; send its rows after every other destination's

## Decision Outcome

Chosen option: "mark slow, share, send last", because it bounds both resources without dropping anything a live
destination is owed.

* `DispatchWorker` keeps `slow_destinations_`: a destination whose last successful attempt took more than
  `slow_attempt_ms / 4` (and which is not failing). A quicker attempt, a failure or the release of its last slot clears the
  mark, so the set is bounded by the destinations that hold a slot.
* The slow destinations hold at most `effective_max_pending_failing` slots between them (half the queue, never below one
  destination's share). Past it a new row for a slow destination is refused at enqueue ("slow destinations' share
  reached"). Rows already queued are never shed or aged out.
* `next_ready_locked` offers a slow destination's oldest row only when no other destination has one ready. Its later rows
  stay behind its oldest, so the per-destination order is unchanged.

### Positive Consequences

* However many names answer slowly, half of the queue stays available to the others, and a thread is never kept from a
  destination that answers quickly for longer than one slow attempt.
* A destination that is merely slow keeps everything it is owed and is still delivered when nothing else is ready.

### Negative Consequences

* A destination is recognised only after its first slow answer, so a first burst to never-seen names can still fill the
  queue; the slow share then stops it growing and the queue drains as the names deliver. Residual risk.
* When other destinations are always ready, a slow one waits, which delays it further.

## Pros and Cons of the Options

### Count a quarter-limit answer as a failure

* Bad, because shedding and the 24 h age limit would discard transactions a live, reachable destination is owed.

### Lower `slow_attempt_ms`

* Bad, because the attacker answers just under whatever value is set, and a lower value penalises honest slow peers.

## Links

* Refines [ADR-0354](0354-federation-delivery-gives-each-destination-at-most-one-thread.md) and [ADR-0621](0621-failing-destinations-share-half-the-dispatch-queue-and-their-transactions-age-out.md)
