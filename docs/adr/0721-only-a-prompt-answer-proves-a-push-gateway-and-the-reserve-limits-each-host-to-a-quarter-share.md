# Only a prompt answer proves a push gateway, and the reserve limits each host to a quarter share

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C48 (resource-exhaustion.push-delivery-slots.proven-gateways-answering-under-half-timeout-hold-every-slot)

## Context and Problem Statement

ADR-0634 keeps a quarter of `server.push.max_in_flight_deliveries` for batches whose gateway hosts "answered promptly
lately", and ADR-0409 defines a prompt answer as one within half the total timeout. A local user with pushers on a few
`host:port` keys of their own can answer every request after 14.9 s: the hosts stay reachable, no failure is recorded, the
batches may use the whole budget, and each holds its slot for 15 s. A message every two seconds keeps all slots full and
every other user's notifications are dropped.

## Decision Drivers

* The pusher URL, and so the gateway host, is chosen by its owner.
* An honest gateway such as Sygnal answers in well under a second.
* A rule keyed on one time threshold lets the attacker pick the answer time just inside it.

## Considered Options

* Count a distinct-user number per host before it gets the reserve
* Queue refused batches
* Prove a host only by an answer within an eighth of the timeout, let a slower answer revoke the proof, and give each host a quarter of its usual share while the reserve is being used

## Decision Outcome

Chosen option: the third.

* `gateway_circuit_outcome` returns `unproven_answer` for an HTTP answer that took more than an eighth of the total
  timeout and at most half of it. `GatewayCircuitBreaker::record_unproven_answer` forgets the host's failures (it did
  answer) and removes its reachable proof. A prompt answer still proves the host; an answer over half the timeout is still
  a failure (ADR-0409).
* While the batches in flight are at or above the unreserved three quarters, `PushBatchAdmission` lets a host carry at
  most `host_cap / 4` (at least 1) of them, so a host that answered promptly once cannot take the whole reserve in one
  burst before its slow answers come back.

### Positive Consequences

* A host that answers in 4 s to 15 s no longer earns the reserve, so it can hold at most the unreserved share, as an
  unknown host does.
* An honest gateway is unaffected: it answers promptly and its batches finish quickly.

### Negative Consequences

* An attacker who answers promptly to some requests and slowly to others can still take `host_cap / 4` of the reserve per
  host, and with many host keys all of it, for one answer time. The pusher caps per user and the registration policy bound
  the number of keys. Residual risk, recorded in the threat model.
* A genuine gateway that is consistently slower than 3.75 s is treated as unproven.

## Pros and Cons of the Options

### Distinct users per host

* Bad, because an attacker with several accounts supplies the users, and it needs new per-host state keyed by user.

### Queue refused batches

* Bad, because ADR-0028 drops rather than queues deliberately, and a queue the attacker can fill is the same problem.

## Links

* Refines [ADR-0409](0409-count-a-slow-gateway-answer-as-a-failure-and-bound-a-delivery-batch.md) and [ADR-0634](0634-a-share-of-the-push-delivery-budget-is-kept-for-gateways-that-answer-and-a-host-carries-an-eighth.md)
