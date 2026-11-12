# One client key holds a sixteenth of the parked-connection budgets, and a readable connection waits a bounded time

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C01 (availability.http-dispatcher.pending-connection-budget-filled-by-few-client-keys)

## Context and Problem Statement

`listeners.max_queued_connections` (1024) bounds the connections that wait for their first request, across every listener,
and `server.http.keep_alive_max_connections` (256) bounds parked keep-alive connections. ADR-0072 caps one client key at
`server.http.max_connections_per_ip` (256) connections, a quarter of the first budget, so five addresses could fill it
and every other client, and every federating server, was refused. A connection that had sent one byte and waited for its
key's worker share (ADR-0077) sat in the parker's ready queue with no deadline, still holding a pending slot, so the
attacker did not even need to race the five-second first-byte timeout.

## Decision Drivers

* No few keys may hold a process-wide budget.
* A trusted reverse proxy carries many clients over one address and is exempt from per-key caps (ADR-0077).
* A legitimate client behind carrier NAT may open several connections.

## Considered Options

* Raise the budget or lower `max_connections_per_ip` by default
* Give a readable connection a deadline only
* A per-key share of each parking budget, plus a bound on the time a readable connection waits

## Decision Outcome

Chosen option: "a per-key share of each parking budget, plus a bound on the time a readable connection waits", because
either part alone fails.

* A client key may hold at most `max(1, budget / 16)` pending slots and the same share of the keep-alive budget (64 and
  16 by default). The count lives in two `http::ConnectionLimiter` instances in the dispatcher, held as a slot on the
  connection for as long as the connection is parked. An empty key (a trusted proxy) and an unbounded budget (`0`) are
  exempt. A key over its share has the new connection closed, and a keep-alive response is sent `Connection: close`.
* `net::ConnectionParker::Limits::max_ready_wait` closes a connection that has been readable that long without a
  worker share. The dispatcher sets it from `HttpServeTuning::ready_wait_timeout` (30 s).

### Positive Consequences

* Sixteen keys, not five, are needed to fill the pending budget, and each key's contribution is only 64.
* A connection can no longer sit in the ready queue for ever.

### Negative Consequences

* A NAT with more than 64 connections still waiting for their first request is refused for the excess.
* Many distinct keys can still share out the pool (ADR-0077 accepts this).

## Pros and Cons of the Options

### Raise the budget or lower the per-IP default

* Bad, because it moves the number of keys an attacker needs without removing the problem, and ADR-0072 already did it once.

### A deadline on the ready state only

* Bad, because the attacker reconnects every few seconds at no cost, so slots stay full.

## Links

* Refines [ADR-0072](0072-per-ip-connection-cap-at-accept-time.md) and [ADR-0077](0077-no-worker-waits-on-a-quiet-connection.md)
