# Reserve a pre-v12 room ID across the policy hook, and pick the first free one

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2, the trap recorded with F-42, and F-82
(`rooms.createroom-pre-v12-room-id-from-localroom-vector-size`)

## Context and Problem Statement

`create_room` for a room version below 12 named the room `!room<N>:<server>` with `N = rooms.size() + 1`, computed
before `resolve_policy_server_hook`. The hook releases `runtime.mutex` for its round trip, so a second creation could
compute the same `N` and store its room first, and the first then failed on the duplicate (500, "room persistence
failed"). While the hook failed at once the window was tiny; once it reaches a real policy server (ADR-0361) the window
is up to `policy_server_timeout`. `rooms.size()` is also not monotonic, because `join_room` can erase an entry while the
persistent row stays.

## Decision Outcome

`create_room` chooses the first `!room<N>` that is neither a room this server holds (in memory or persisted) nor a
reservation, and holds a `RoomIdReservation` (an RAII entry in `HomeserverRuntime::rooms_being_created`, guarded by
`runtime.mutex`) from the choice until the function returns, whatever the outcome. A creation that runs while the first
waits on the hook sees the reservation and takes the next number. Version 12 needs no reservation: its ID is the hash of a
create event stamped strictly after the last one composed (ADR-0156).

Rule for future code: an identifier derived from state, then used after a call that releases `runtime.mutex`, must be
reserved before the call and checked against the reservations of other threads.

### Negative Consequences

* A policy rule for a room entity named `!room<N>:<server>` is evaluated for the number chosen before the hook; with a
  concurrent creation that number is simply different from what a count alone would give.

## Links

* Related to [ADR-0361](0361-the-policy-server-is-an-operator-trusted-destination-resolved-in-the-hook-and-admitted-through-a-budget.md)
