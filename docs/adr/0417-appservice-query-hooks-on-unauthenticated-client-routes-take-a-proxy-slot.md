# Appservice query hooks on unauthenticated client routes take a proxy slot

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-68 (`cs.unauthenticated-appservice-query-hooks-without-outbound-slot`)

## Context and Problem Statement

`GET /profile/{userId}` and `GET /directory/room/{roomAlias}` are served before authentication. For an
identifier unknown here that falls in a registered appservice's users or aliases namespace, each calls
the appservice (`query_user`, `query_room_alias`) with `runtime.mutex` released, but the request thread
stays held for up to the appservice timeouts (10 s connect, 30 s total, per matching registration).
Neither route took a client outbound proxy slot. Behind a trusted reverse proxy the per-client worker
share does not apply, so one client could keep every main-pool thread inside appservice calls while a
bridge was slow. `docs/http-transport.md` and `docs/threat-model.md` listed these hooks as "not
covered" because the operator chooses the destination; ADR-0181 had already rejected that reasoning for
the `/thirdparty/*` routes.

## Decision Drivers

* ADR-0079: every client request that makes this server wait on another party takes a slot.
* ADR-0181: the budget only works if every client-triggered outbound route takes part.
* A server with no matching appservice must not answer 429.
* The Application Service API's query semantics must not change.

## Considered Options

* Take one slot per request, only when a registration matches, hold it until the loop ends, answer
  `429 M_LIMIT_EXCEEDED` when none is free
* Treat a refused slot as a miss and answer 404
* Leave the hooks outside the budget because the operator picks the destination

## Decision Outcome

Chosen option: "one slot per request, 429 when refused". Both handlers test whether any registration's
namespace matches the identifier and take `admit_client_proxy` once, before the first
`RuntimeLockRelease`, only if one does. The slot is held until the loop over registrations ends and
dropped by its destructor. A refusal is `429 M_LIMIT_EXCEEDED` with `retry_after_ms`, the answer every
other proxied lookup gives. An identifier outside every namespace needs no slot.

### Positive Consequences

* One client holds at most its share of request threads in appservice calls, as for every other proxied
  route.

### Negative Consequences

* A client that is refused is told to retry; a client sharing an address with a busy one may see 429
  for an identifier the appservice would have answered.
* The query is still not under an `OutboundDeadline`: the appservice client has no deadline parameter,
  as in ADR-0181.

## Pros and Cons of the Options

### Treat a refusal as a miss

* Good, because a refused lookup answers like an unknown identifier.
* Bad, because a bridge-created user or alias is reported absent, which a client cannot tell from the
  real answer; ADR-0181 did not choose it either.

### Leave the hooks outside the budget

* Bad, because it leaves the pool-starvation condition the budget exists to prevent.

## Links

* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
* Refines [ADR-0181](0181-third-party-lookups-take-a-client-outbound-proxy-slot.md)
