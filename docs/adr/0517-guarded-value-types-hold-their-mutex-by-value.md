# Guarded value types hold their mutex by value

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

`PersistentStore` and `FederationRuntimeState` are returned and moved by value, yet each guards some members with a
mutex. A `std::mutex` can be neither copied nor moved. Both types kept the mutex behind a `std::unique_ptr` or
`std::shared_ptr` so the type stayed movable. SonarCloud flagged the allocation (`cpp:S8474`) and the public mutable
member (`cpp:S8379`). How should a copyable or movable type own a mutex?

## Considered Options

* Keep the mutex behind `std::unique_ptr` or `std::shared_ptr`.
* Delete the copy and move operations of the owning types.
* `core::CopyableMutex` and `core::CopyableConditionVariable`, held by value.

## Decision Outcome

Chosen option: "`core::CopyableMutex` and `core::CopyableConditionVariable`, held by value". Copy and move construct a
fresh unlocked mutex and assignment leaves the target's mutex alone, all `noexcept`. The only locking API is
`acquire() const`, which returns the `std::unique_lock`. The condition variable wraps `std::condition_variable`, not
`condition_variable_any`, whose constructor allocates under libstdc++ and would make the move throw.

### Negative Consequences

* Copying or moving an owner while its mutex is held is a bug: the copy is not protected by the source's lock. Callers
  copy a store only while no other thread uses it.
* Copies of `FederationRuntimeState` no longer share one mutex, as they did through the `shared_ptr`.

## Pros and Cons of the Options

### unique_ptr or shared_ptr to a mutex

* Bad, because every object allocates, and a moved-from object has a null mutex.
* Bad, because `shared_ptr` shares one mutex between copies, tying unrelated copies together.

### Delete the copy and move operations

* Bad, because the stores are returned by value; deleting the operations breaks every such return.
