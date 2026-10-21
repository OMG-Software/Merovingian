# Third-party lookups take a client outbound proxy slot and keep per-appservice timeouts

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `sp02.thirdparty-no-proxy-slot`

## Context and Problem Statement

ADR-0079 requires every client request that makes this server call another one to take a slot of
the client outbound proxy budget first, so lookups that wait on slow peers cannot hold every
request thread. The `/thirdparty/*` routes call the registered appservices and took no slot. The
bare `location?alias=` and `user?userid=` routes call every appservice in turn.

## Decision Drivers

* The budget only works if every client-triggered outbound route takes part.
* A server with no appservice to call must not answer 429.
* Aggregated results should not be cut short.

## Considered Options

* Take a slot on every route that will call an appservice; keep each appservice's own timeout
* Take a slot and also run the whole route under one shared deadline

## Decision Outcome

Chosen option: "take a slot; keep each appservice's own timeout". Each of the six routes takes a
slot before `runtime.mutex` is released, holds it until it returns, and answers
`429 M_LIMIT_EXCEEDED` with `retry_after_ms` when none is free. It takes one only when it will call
an appservice: one with protocols for `/protocols`, the protocol's owners for the `{protocol}`
routes, and any registered appservice for the bare routes.

### Positive Consequences

* A client's third-party lookups count against the same per-client and global caps as directory and
  media lookups.

### Negative Consequences

* A request still takes up to the sum of the appservices' timeouts, though it holds only its one
  slot while it does.

## Pros and Cons of the Options

### One shared deadline

* Good, because it bounds a request's duration.
* Bad, because the appservice client has no deadline parameter, and a deadline would drop later
  appservices' answers from the aggregate.

## Links

* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
