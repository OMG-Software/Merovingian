# A share of the push delivery budget is kept for gateways that answer, and one host carries an eighth of it

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `resource-exhaustion.push-delivery-slots.many-accounts-and-gateway-hosts-hold-every-delivery-slot`

## Context and Problem Statement

Background push delivery runs one task per recipient, `server.push.max_in_flight_deliveries` (256) in all, and a batch
holds its slot for up to twice the total timeout. A pusher's gateway URL is chosen by its owner. The per-gateway limits
(32 requests per host name, 64 per address) and the circuit breaker only bound how many requests reach one gateway:
33 accounts on eight freshly minted host names whose addresses never answer hold all 256 slots, and every other user's
delivery is dropped (ADR-0028). The breaker records a failure only when a request ends, after the slots are taken, and
it keys on the host name, which the attacker mints. How can no set of gateways or recipients hold every slot?

## Decision Drivers

* A gateway that is alive must not lose a delivery because other gateways are dead.
* A host that has never been contacted cannot be told from a dead one in advance.
* No new setting: the caps follow `max_in_flight_deliveries`.

## Considered Options

* Reserve a quarter of the budget for recipients whose gateway hosts have all answered promptly lately, and let one host
  carry an eighth of the budget
* Reserve a share for recipients with "no failing pusher" (no failure in the breaker)
* Charge only the host, with no reserve
* Queue a batch that finds the budget full instead of dropping it

## Decision Outcome

Chosen option: "reserve a quarter for reachable hosts, an eighth per host".

* `GatewayCircuitBreaker::reachable_recently(host)` is true when a request to the host answered promptly (the existing
  `GatewayCircuitOutcome::reachable`: not a transport failure, not slower than half the total timeout) within an hour
  and the host has not failed or answered slowly since. The set is bounded by `max_hosts`, oldest forgotten first.
* `PushBatchAdmission::admit` refuses a batch when the batches in flight are at the whole budget, or at three quarters
  of it unless every host of the batch is reachable, or when one of its hosts already carries an eighth of the budget
  (a `GatewayInFlightLimiter` slot per host, held while the batch runs). A budget under 4 reserves nothing.
* A refusal is the existing drop with its log line (ADR-0028), with the reason in `scope`.

"No failing pusher" was rejected: a freshly minted host has no failure until its first request ends, which is after the
slots are taken, so an attacker's first wave counts as clean and fills the reserve. Positive proof of an answer cannot
be had by waiting. A host with no history shares the unreserved three quarters, so under an attack a brand new
legitimate gateway can lose a delivery until its first prompt answer; every gateway that has answered keeps its place.
Queueing was rejected here: a queued batch holds memory and a place in line for as long as the slow gateways take, and
the event is on the client's next `/sync` anyway (ADR-0028).

### Negative Consequences

* A shared gateway cannot have more than an eighth of the budget in flight at once (32 at the default), the same as the
  existing per-host request limit.
* After a restart no host is reachable until it answers once, so for that first answer all hosts share three quarters.

## Links

* Refines [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md),
  [ADR-0151](0151-cap-pusher-registration-and-break-the-circuit-to-failing-gateways.md) and
  [ADR-0409](0409-count-a-slow-gateway-answer-as-a-failure-and-bound-a-delivery-batch.md)
