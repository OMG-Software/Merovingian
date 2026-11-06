# PersistentStore copies are defaulted

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

`PersistentStore` had a hand-written copy constructor and copy assignment that listed its members one by one. They were
written in 0.10.31, when the store's mutexes could not be copied. `state_transitions` and `state_transition_index` were
added 18 days later (0.11.2, Matrix v1.19 phase 2) without joining the list. A copy therefore held no state transitions,
and `find_state_transition` on it found nothing. That function feeds `unsigned.replaces_state` and the membership walks of
`HistoryVisibility` and `room_read_access_for`, which fail closed when a transition is missing.

Compiling the whole tree with the copy operations deleted shows that no production code copies a store. Only tests do
(`test_database_persistence.cpp`, `test_key_signature_index.cpp`, `test_federation_conformance.cpp`). The defect was
latent. Since ADR-0517 the mutexes are `core::CopyableMutex`, which copy as fresh unlocked mutexes, so the reason for
the hand-written list is gone. How should the store be copied?

## Considered Options

* Keep the hand-written list and add the two missing members.
* Default the copy constructor and copy assignment.
* Delete the copy operations, since the server never copies a store.

## Decision Outcome

Chosen option: "Default the copy constructor and copy assignment". A defaulted copy names no members, so a member added
later is copied without anyone remembering to list it, which is the mistake that caused this defect. The copy behaves
as before for every other member: the hand-written list copied all of them, and `CopyableMutex` gives the same fresh
mutexes the list gave by leaving them out.

### Positive Consequences

* A copy carries every member and every index, now and for members added later.
* About 200 lines of member list are gone.

### Negative Consequences

* A member that must not be copied now needs its own copy semantics (as `CopyableMutex` has), not an omission from a
  list. Nothing in the store needs that today.

## Pros and Cons of the Options

### Keep the hand-written list and add the two members

* Good, because it is the smallest change.
* Bad, because the list has to be kept in step with roughly a hundred members by hand, and that already failed once.

### Delete the copy operations

* Good, because the server never copies a store, so nothing in production can copy one by accident.
* Bad, because ADR-0517 chose to keep the owning types copyable, and tests rely on copies to check that the indexes
  survive one. Deleting reverses that decision to fix a defect the default fixes too.

## Links

* Builds on [ADR-0517](0517-guarded-value-types-hold-their-mutex-by-value.md)
