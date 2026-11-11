# Failing destinations share half the dispatch queue, and their transactions age out

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, resource-exhaustion.dispatch-worker.sixteen-dead-destinations-fill-shared-outbound-queue

## Context and Problem Statement

[ADR-0177](0177-each-outbound-destination-holds-a-bounded-share-of-the-dispatch-queue.md) gives each destination a sixteenth of
the outbound queue, so one dead peer cannot fill it. It bounds one peer, not the number of peers: sixteen peers that
stop answering hold all 4096 slots, and every other destination's transactions are refused. A transaction leaves only
after `max_retries` attempts, and only a destination's oldest is tried, so 256 of them held their slots for weeks.

## Considered Options

* A lower per-destination share
* A shared limit on what destinations that are failing may hold, and an age limit
* Evict the oldest transaction of a dead destination when a live one needs room

## Decision Outcome

Chosen option: a shared limit and an age limit.

* A destination is failing while its `consecutive_failures` is above zero. Failing destinations hold at most
  `effective_max_pending_failing` slots between them: half of `max_queue_depth`, so the other half can only be taken by
  destinations that are not failing. No operator key: like the per-destination share, it derives from the depth. It is
  never below one destination's own share (`effective_max_pending_per_destination`): it bounds many dead peers together,
  and one destination that fails once must not lose what ADR-0177 lets it hold. A queue of 32 or fewer, where that share
  is already half of it or more, gets no reserve from this rule.
* `enqueue_batch` refuses a transaction for a failing destination once that share is spent, unless the destination's
  backoff has ended. Past its backoff it is due a try, and only a try can show it has recovered: refusing it would
  leave a recovered destination failing for as long as others hold the share.
* When a destination starts failing and the share is exceeded, the failing destinations are cut to a common limit
  (the largest number each may keep so that all fit), newest first, so each keeps the transactions it is retrying and
  small holders lose nothing. A destination that is not failing is never cut.
* A failing destination's transaction older than `max_failing_transaction_age_ms` (24 hours) is deleted, from the queue,
  the replay list and the database, in one commit per pass. The worker walks the queue at most once a minute. The age is
  read from the transaction's `origin_server_ts`, which `enqueue_batch` stamps when it is empty; that field is stored and
  is not what is sent, so no migration is needed.
* A dropped transaction costs the peer nothing it cannot recover: once reachable it fetches what it missed
  (`prev_events`, `/get_missing_events`), as ADR-0177 already relies on.

A lower share was rejected because it still does not bound the number of peers and would hurt a single busy live peer.
Evicting on demand was rejected because it makes each enqueue, which runs under `runtime.mutex`, do work that depends
on how many peers are failing.

### Negative Consequences

* Until a new destination has failed once it counts as live, so a burst to many never-seen dead peers can fill the queue
  for the length of one attempt each. Their first failures then cut them to the share.
* Slots of attempts in flight cannot be cut, so the share can be exceeded by at most `delivery_threads`.

## Links

* Refines [ADR-0177](0177-each-outbound-destination-holds-a-bounded-share-of-the-dispatch-queue.md)
* Relates to [ADR-0354](0354-federation-delivery-gives-each-destination-at-most-one-thread.md)
