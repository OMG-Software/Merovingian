# Count a slow gateway answer as a failure, bound a delivery batch by a deadline, and cap requests per gateway host and address

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-79 (a push gateway that answers just under the
timeout never opens its circuit, so colluding accounts can hold the delivery slots)

## Context and Problem Statement

A recipient's batch holds one of `server.push.max_in_flight_deliveries` (256) slots until every one
of that recipient's pushers has been contacted in turn. A pusher's gateway URL is chosen by its
owner. ADR-0151's circuit breaker counts only transport failures and treats every HTTP answer, however
late, as proof the host is reachable, on the stated ground that a gateway that answers does so
promptly and one that stalls ends in a counted timeout. A hostile gateway can answer at 29 s against
a 30 s timeout for ever: it never times out, never opens its circuit, and a recipient with 20 pushers
on it holds a slot for about 580 s. With 8 slots allowed per recipient, about 33 accounts fill the
budget, and every other user's push is then dropped (ADR-0028). ADR-0140 accepts that several
recipients can collectively fill the budget; it does not accept a gateway that makes each of them hold
a slot for ten minutes, and ADR-0151's promptness assumption is false for such a gateway.

## Decision Drivers

* Keep ADR-0151's rule that one notification's 5xx must not close a host that other users share.
* A slot's hold time should not be the number of pushers times the timeout.
* A per-host breaker alone is sidestepped with many subdomains of one server.
* No new configuration: the numbers follow from `total_timeout_seconds` and `max_in_flight_deliveries`.

## Considered Options

* Count an answer slower than half of `total_timeout_seconds` as a breaker failure, bound each batch
  by a deadline, and cap requests in flight per gateway host and per resolved address
* Count every 5xx, and slow answers, as breaker failures
* Cap only per registering account
* Shorten `total_timeout_seconds`

## Decision Outcome

Chosen option: the first, in three parts.

* **A slow answer is a failure.** `push::gateway_circuit_outcome(result, elapsed, total_timeout)`
  returns `slow_answer` for an HTTP answer that took longer than half of the client's total timeout,
  and `attempt_push_delivery` records it against the host's circuit like an unreachable gateway. This
  keeps ADR-0151's reasoning: a 5xx is about one notification, and one user's bad pusher data cannot
  easily make a shared host slow, so a slow answer is about the host. A shared gateway that is
  genuinely slow is skipped for the cooldown, as one that cannot be connected to is.
* **A batch has a deadline.** `run_pending_push_deliveries` stops contacting gateways once a batch has
  run for twice `total_timeout_seconds` (60 s by default) and queues the pushers it has not reached
  (`defer_push_delivery`, without counting a failed attempt). A slot is therefore held for the
  deadline plus one attempt, 90 s at most by default, against 580 s.
* **Requests in flight are capped per gateway host and per resolved address**
  (`push::GatewayInFlightLimiter`, taken by `PushGatewayClient::notify` for the length of the
  request). A host may have an eighth of `max_in_flight_deliveries` in flight (32), an address a
  quarter (64), at least two each, or the whole budget when it is smaller: with a budget of two, a single shared
  address would otherwise serialise every delivery. The address cap is the one that holds when a server is reached
  under many names. A request over a cap is not sent, is not counted against the circuit, and is
  retried (`PushGatewayResult::busy`).

The numbers: half the timeout is the line between a gateway that is slow for a push and one that is
merely distant; an eighth and a quarter leave room for several large legitimate gateways in the
budget while meaning at least four addresses, not one, are needed to fill it; two timeouts gives a
batch room for several pushers on working gateways.

### Positive Consequences

* A gateway that answers just inside the timeout is skipped after `gateway_failure_threshold` (3)
  slow answers, and holds no more slots until its cooldown ends.
* A recipient's batch can no longer hold a slot for pushers times the timeout.
* Filling the budget needs several addresses, not many names for one.

### Negative Consequences

* This refines ADR-0140's fairness residual and does not remove it: several recipients can still
  collectively fill the budget with several addresses' worth of slow gateways, for the deadline.
  Fairness among recipients is still not promised.
* This corrects ADR-0151's negative consequence, which said a gateway answering with a 5xx answers
  promptly so the slot is short: the slot is short only if the answer is prompt. A slow 5xx now counts
  against the circuit; a prompt one still does not.
* A working gateway that is slow (answers in more than half the timeout) three times in a row loses
  its notifications for the cooldown, which are queued for retry and not dropped.
* A very large legitimate gateway receiving more than 32 simultaneous requests from this server has the
  excess retried after the first backoff.

## Pros and Cons of the Options

### Count every 5xx

* Good, because it would also stop a gateway that fails slowly.
* Bad, because ADR-0151 rejected it for good reason: one user's pusher can make a shared gateway
  answer 5xx for that notification.

### Cap only per registering account

* Good, because the registrant is known.
* Bad, because accounts are cheap where registration is open, and it caps nothing about the remote server.

### Shorten the total timeout

* Good, because it reduces every hold time.
* Bad, because it does not stop a gateway answering just inside it, and it would cut off real gateways.

## Links

* Refines [ADR-0140](0140-isolate-push-delivery-capacity-per-recipient.md) (its fairness residual)
* Corrects the promptness assumption of [ADR-0151](0151-cap-pusher-registration-and-break-the-circuit-to-failing-gateways.md)
* Related to [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md) and
  [ADR-0206](0206-retry-failed-push-notifications-from-a-bounded-in-memory-queue.md)
* Continued in [ADR-0410](0410-bound-the-push-retry-thread-by-time-and-take-retries-in-turn.md) for the retry thread
