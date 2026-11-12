# A decided make_join race starts no further calls, is run by a fixed number of workers, and holds its request's slot to the end

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C33 (resource-exhaustion.make-join-race.orphaned-candidates-keep-running-after-client-outbound-slot-is-released)

## Context and Problem Statement

`POST /join` to a room this server is not in races `make_join` against up to 20 candidate servers. The request held one
client-outbound slot only until the race returned (first answer, or the 45 s race deadline `join_race_deadline_seconds`, which
is off when 0). Every candidate task that had not finished was parked in `runtime.orphan_futures_` and kept going: one thread
per candidate, started up front; a queued candidate bailed out only when a winner existed, so after the caller gave up each
still made its full call (up to 180 s with discovery) with no deadline of its own. Nothing capped how many such orphans
existed, so a user naming unresponsive servers could repeat joins and accumulate threads, copies of the signing key and
sockets far beyond the client-outbound budget meant to bound this work.

## Decision Drivers

* Background work started for one client request stays inside that request's budget for its whole life, including when
  `join_race_deadline_seconds` is its default of 0.
* The first successful answer still wins, and the request need not wait for the losers.

## Considered Options

* Only a `cancelled` flag and the race deadline as each call's deadline
* A global cap on orphaned join tasks, like `push_delivery_in_flight_`
* A fixed number of workers pulling candidates, a `cancelled` flag, the race deadline when set, and the request's
  client-outbound slot held by the race until its last worker ends

## Decision Outcome

Chosen option: the third. All of it lives in `MakeJoinRaceState` (its own header):

* **Workers.** `worker_count(parallelism, candidates)` threads at most (`join_parallelism`, default 8), each looping on
  `next_candidate()`. There is no thread per candidate and no semaphore. A worker takes a candidate only when it is free to
  call it.
* **Cancel.** `cancel()` is called as soon as the caller stops waiting. `next_candidate()` hands out nothing once there is a
  winner or the race is cancelled and counts the candidates not yet taken as finished, so a cancelled worker starts no call.
* **Deadline.** Every call carries `BoundedOutboundLimits` on `join_race_deadline_seconds` when it is set.
* **Slot.** `perform_federated_join` takes the caller's `std::optional<http::InFlightBudget::Slot>*` and the race adopts it
  (`adopt_slot`). The last worker to end (`worker_finished`, from an RAII `MakeJoinWorkerExit`, so an exception releases too)
  frees it. A client's per-client and global budgets therefore still count a join while any of its calls runs, so the number
  of orphaned calls is bounded by the client-outbound budget (`pool/2` joins, one per client) times `join_parallelism`, even
  with no race deadline. A race whose workers had all ended before the adoption releases the slot at once.

### Positive Consequences

* With the default settings the lifetime of background work is bounded by `join_timeout_seconds` and the slot is held for it.
* After a deadline with no winner, nothing new starts; with a deadline set, in-flight calls end at it too.
* Threads per join are at most `join_parallelism`, not the candidate count.

### Negative Consequences

* A join whose winner came quickly keeps its client's slot while slower losers finish (up to the race deadline, or the join
  timeout with none). That client cannot start another outbound proxy request meanwhile; this is the intended price, as the
  losers still hold sockets and a thread.
* `join_through_other_resident` hands its slot over the same way, so a failed fallback leaves the slot with the race.

## Pros and Cons of the Options

### Only a flag and the deadline

* Bad, because with the default of no race deadline the in-flight calls were unbounded and the slot was released early.

### A global cap on orphans

* Bad, because it bounds the damage but not the lifetime; holding the slot bounds both with the budget that already exists.

## Links

* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
