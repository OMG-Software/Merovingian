# One membership exchange per user and room at a time

* Status: accepted
* Date: 2026-10-28

Technical Story: review of PR #541 (a `/leave` during a remote knock)

## Context and Problem Statement

A federated join, knock or leave asks another server and then writes the user's membership. The
request lock is released for the exchange (the runtime lock may not be held across a network
call, `src/homeserver/AGENTS.md`), so a second `/join`, `/knock` or `/leave` by the same user for
the same room can run meanwhile. Its result is then overwritten when the first commits: a
`/leave` during a knock finds no membership, answers 200, and the accepted knock is stored after
it, so the user is told the knock was withdrawn while it stands. How should the second request
be handled?

## Considered Options

* Refuse it with 429 while the first is in flight
* Make it wait for the first to finish
* Let the first re-check the membership before it commits, and drop or undo its result

## Decision Outcome

Chosen option: "refuse it with 429", because it is the only one that is both simple and correct
for every interleaving. `HomeserverRuntime::membership_exchanges` holds the (room, user) pairs
with an exchange in flight; `MembershipExchangeClaim` (RAII, in `room_service.cpp`) adds the pair
before the lock is released and removes it when the operation returns. `join_room`, `knock_room`
and `leave_room` refuse a claimed pair with 429 `M_LIMIT_EXCEEDED` and `retry_after_ms`, a
response the Client-Server API lists for all three endpoints, before reading or writing anything.

### Positive Consequences

* A membership change the user is told succeeded is never overwritten by one already in flight.

### Negative Consequences

* A client that sends two membership changes for one room at once has one refused and must retry.
* A new path that changes a user's own membership over federation must take the claim, and a new
  entry point that changes it must check it.

## Pros and Cons of the Options

### Make it wait

* Bad, because a waiting request holds a request thread for up to the exchange's whole deadline,
  and a user could tie up the pool with requests for rooms whose residents are slow.

### Re-check before committing

* Bad, because a `/leave` that found no membership wrote nothing, so there is nothing to detect,
  and undoing an accepted remote knock or join needs another exchange that can itself fail.
