# A restricted join waits for in-flight room events before it is refused or sent away

* Status: accepted
* Date: 2026-10-30

Technical Story: Complement run 12 (`TestRestrictedRoomsLocalJoinNoCreatorsUsesPowerLevelsV11`/`V12`)

## Context and Problem Statement

An event for a room from another server is applied under that room's stripe mutex
(`runtime.room_stripe_mutexes`) and then `runtime.mutex`. A local join of a restricted room
decides under `runtime.mutex` alone. A power-levels event that gives a local user the power to
invite can therefore be received, and be part-way through being applied, when the join decides
from state that does not hold it yet (Complement saw it 3 ms apart). The join found no local user
able to authorise it and, before ADR-0287, was refused; now it would be sent to another resident,
and the user would be authorised by a user of another server although a local user could have.

## Considered Options

* Decide once, from the state at that moment
* When the verdict is `unable_to_grant`, wait for the room's in-flight events and decide again
* Hold the room stripe for the whole decision

## Decision Outcome

Chosen option: "wait and decide again". `join_room` takes the membership exchange claim, releases
`runtime.mutex` (`RuntimeLockRelease`), locks and releases the room's stripe mutex, restores
`runtime.mutex`, finds the room again and decides a second time. The stripe is held only for
that wait, so the order is stripe then runtime lock, as ingestion takes them. It costs nothing on
the common path: only the `unable_to_grant` verdict waits, and only for events already being
applied. An event still in the transport is not waited for; that residue is what ADR-0287's
fallback is for.

## Pros and Cons of the Options

### Decide once

* Bad, because it turns a 3 ms race into a refusal or a remote authorisation.

### Hold the room stripe for the whole decision

* Bad, because `join_room` composes and persists with `runtime.mutex` held, and ingestion takes
  the stripe before the runtime lock: holding the stripe through a section that may wait on other
  locks widens the lock-order surface for no gain over a wait that ends before the decision.

## Links

* Refines [ADR-0287](0287-a-resident-with-no-local-authoriser-joins-its-user-through-another-resident.md)
