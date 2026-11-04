# Bound the push retry thread by time, take retries one recipient at a time in turn, and use a shorter timeout for retries

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-81 (one account's slow gateway can occupy the single
push retry thread)

## Context and Problem Statement

ADR-0206 sends every retry from one `PeriodicJob` thread, one at a time, up to 32 per run, in due
order, and accepts that a slow gateway delays the retries behind it by at most the client timeout
each, relying on the circuit breaker to skip hosts that keep failing. The breaker did not skip a host
that answers with an error just inside the 30 s timeout (ADR-0151: any HTTP answer is "reachable"), and
a run of 32 such retries is about 16 minutes. Backoff is at most 10 minutes, so one account's 32
entries are all due again by the next run, and another user's retry that falls due during a run waits
for the whole of it. ADR-0151's rule that one notification's 5xx does not open a shared host's circuit
must stay.

## Decision Drivers

* The retry thread is shared by every user's retries, so what one user's gateway costs it must be
  bounded in time, not in the number of entries.
* Shutdown and the retry queue's durability must not suffer.
* Retries are a spec SHOULD and not what a user is waiting for.

## Considered Options

* A per-run time budget, retries taken one recipient at a time in turn, and a shorter timeout for
  retries
* Count every 5xx against the circuit
* A pool of retry threads
* Charge elapsed time to each user and skip a user who has used their share

## Decision Outcome

Chosen option: the first.

* `retry_due_push_deliveries` starts no attempt once it has run for `push_retry_batch_budget` (30 s).
  The retries it had taken and not reached, and those it had taken when a stop is requested, go back
  to the queue unchanged with `PushRetryQueue::return_untried` (same due time and attempt count), so
  nothing is lost and they are first in line at the next run. Shutdown still waits for at most the
  attempt in flight.
* `PushRetryQueue::take_due` takes due retries round robin by recipient: the first of each
  recipient with a due retry, earliest-due recipient first, then the second of each, and so on. One
  recipient's backlog cannot stand in front of the others.
* Retries are sent with a total timeout of at most `push_retry_total_timeout` (10 s) and a connect
  timeout of at most 5 s (`push_retry_config`), against 30 s and 10 s for a first attempt. A retry's
  slow answer is judged against that shorter timeout (ADR-0409).

With these a run is at most 30 s plus one attempt (40 s) instead of 16 minutes, and another user's
retry is reached within a handful of attempts rather than after a whole backlog.

### Positive Consequences

* One account's slow gateway can delay another user's retry by about one attempt, not a run.
* Retries not reached stay queued and keep their place; a stop loses none.
* ADR-0151's rule is kept: no circuit opens on one notification's 5xx.

### Negative Consequences

* Updates the negative consequence of [ADR-0206](0206-retry-failed-push-notifications-from-a-bounded-in-memory-queue.md),
  which said a slow gateway delays the retries behind it by at most the client timeout each and that the
  breaker skips hosts that keep failing: the delay is now bounded per run by the budget, and the breaker
  skips a host that answers slowly only through ADR-0409.
* A gateway that needs more than 10 s to answer a retry will not succeed on one, though it may on a
  first attempt.
* With many accounts each holding a slow gateway the thread still spends its budget on them, in turn.
  Their retries age toward the same give-up as any other and no account's retry is starved, but the
  throughput of the thread is not raised. Charging elapsed time per user was not done: round robin
  with a budget bounds the damage without per-user accounting.
* `return_untried` can take the queue past its bounds by at most one batch (32) until that batch is
  sent.

## Pros and Cons of the Options

### Count every 5xx against the circuit

* Bad, because ADR-0151 rejected it: one user's pusher would close a gateway shared by many.

### A pool of retry threads

* Good, because slow gateways would overlap.
* Bad, because it multiplies the threads a hostile gateway can hold and needs its own admission.

### Charge elapsed time per user

* Good, because a slow user would spend only their own share.
* Bad, because it needs a table of per-user state for little gain once the batch is time-bounded and
  taken in turn.

## Links

* Updates the negative consequence of [ADR-0206](0206-retry-failed-push-notifications-from-a-bounded-in-memory-queue.md)
  and the promptness assumption of [ADR-0151](0151-cap-pusher-registration-and-break-the-circuit-to-failing-gateways.md)
* Builds on [ADR-0409](0409-count-a-slow-gateway-answer-as-a-failure-and-bound-a-delivery-batch.md)
