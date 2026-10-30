# Waiting requests and outbound calls share the global cap

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: PR #546 review

## Context and Problem Statement

ADR-0079 bounds client-triggered outbound calls at half the request pool, so the other half always serves
requests that never leave this server. ADR-0306 and ADR-0307 let an authenticated request (a timestamp
lookup, an invite offer) wait for its slot instead of being refused at once. A waiting request sleeps on a
request thread, and ADR-0306 bounded that by each client's connection share (ADR-0077). That bound is per
client: many clients each waiting, alongside a full set of calls in flight, could hold the whole pool.

## Considered Options

* Count waiters and calls in flight as one population under the global cap
* Cap waiters separately
* Keep the per-client bound only

## Decision Outcome

Chosen option: "Count waiters and calls in flight as one population under the global cap". A request may
start waiting only from a place `InFlightBudget::try_reserve_wait` grants while calls in flight plus waiters
are under the global cap; `try_acquire` counts waiters too, so a new request never takes the room a waiter
holds; and a waiter becomes a call under the per-client cap alone, the population unchanged. So a request
waits only for its own client's slot, and with the population full it is refused at once (429, or the
invite goes to the retry queue). A separate waiter cap would still let calls and waiters together exceed
half the pool.

### Positive Consequences

* Calls in flight and waiting requests together never hold more than half the request pool.

### Negative Consequences

* Under load a lookup that could have waited is refused at once.

## Links

* Refines [ADR-0306](0306-timestamp-to-event-waits-for-a-client-outbound-slot.md)
* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
