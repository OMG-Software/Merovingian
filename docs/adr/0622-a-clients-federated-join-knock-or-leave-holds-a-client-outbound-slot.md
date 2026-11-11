# A client's federated join, knock or leave holds a client-outbound slot

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, resource-exhaustion.client-membership-exchange.federated-join-and-knock-hold-pool-threads-without-outbound-slot

## Context and Problem Statement

`join_room`, `knock_room` and `leave_room` release `runtime.mutex` for their exchange with a resident, but
`RuntimeLockRelease` frees the mutex, not the request thread. A client naming slow `via` servers held a main-pool thread
for each exchange, with no limit but the connection share: the defect
[ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md) exists to prevent. `PendingJoinLease` and
`MembershipExchangeClaim` bound only joins per room and exchanges per (room, user).

## Considered Options

* Take a slot only for `POST /join` and `POST /knock`
* Take a slot on all three, immediately or not at all
* Take a slot on all three, waiting for one as remote invites do (ADR-0306)

## Decision Outcome

Chosen option: a slot on all three, taken at once.

* Each function takes `admit_client_outbound_proxy` on its federated branch only, before its `MembershipExchangeClaim`,
  and holds the RAII slot until it returns. With none free it answers `429 M_LIMIT_EXCEEDED` with
  `retry_after_ms`, as the other client-outbound calls do, having read and changed nothing. A join, knock or leave this
  server decides locally takes no slot, so a full budget never refuses it.
* A join through another resident (ADR-0287) takes the slot too, and a refusal there is the 429, not the 403 that a failed
  attempt falls back to: telling a client it may not join because this server is busy would be wrong.
* The client key comes from the route, as a last parameter defaulting to empty. Callers that never reach the
  federated branch (the room upgrade's leave of its own room, the smoke flow) leave it out.

Leave takes a slot too, though it is a user getting out of a room: a leave is the same exchange and holds the same
thread. Waiting was rejected because a waiter holds a request thread as well; the client retries on the 429.

## Links

* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
* Relates to [ADR-0252](0252-one-membership-exchange-per-user-and-room-at-a-time.md)
