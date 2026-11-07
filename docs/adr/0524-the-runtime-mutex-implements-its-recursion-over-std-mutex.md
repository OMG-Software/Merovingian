# The runtime mutex implements its recursion over std::mutex

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

`HomeserverRuntime::mutex` (`homeserver::RuntimeMutex`) is recursive by design: a request handler that holds it calls
service functions that take it again. It wrapped a `std::recursive_mutex` and recorded the owning thread and the
recursion depth beside it (ADR-0002), because `std::recursive_mutex` cannot say whether the calling thread owns it and
`RuntimeLockRelease` must drop every level the thread holds (ADR-0004). SonarCloud flags every `std::recursive_mutex`
(`cpp:S8462`) and the depth as an unguarded `mutable` field (`cpp:S8379`). The depth was kept twice: once by the
standard mutex, once by this type.

## Considered Options

* Keep `std::recursive_mutex` and the parallel owner and depth.
* Make the runtime mutex non-recursive.
* Implement the recursion in `RuntimeMutex` over a plain `std::mutex`, from the owner and depth it already records.

## Decision Outcome

Chosen option: "Implement the recursion over a plain `std::mutex`". `lock()` by the owning thread only raises the
depth; any other thread takes the mutex, then sets the depth to one and publishes itself as owner. The last `unlock()`
clears the owner and then releases the mutex. The owner and the depth are atomics, so every member the `const` lock
functions change is a mutex or an atomic. A thread that reads its own ID as the owner holds the mutex, because no other
thread ever writes that ID.

The behaviour is unchanged: the same calls nest, `held_by_current_thread()` gives the same answers, and
`RuntimeLockRelease` releases every level and restores them.

### Negative Consequences

* The recursion is hand-written. A change to `lock`, `try_lock` or `unlock` must keep the order: owner published after
  the mutex is taken, cleared before it is released.

## Pros and Cons of the Options

### Keep std::recursive_mutex

* Good, because the standard type implements the recursion.
* Bad, because the owner and depth are needed anyway and the depth is then kept in two places.

### Make the runtime mutex non-recursive

* Good, because recursion hides re-entry into half-updated state.
* Bad, because handlers and service functions nest by design; making it non-recursive is a redesign of every caller,
  not a change this ADR can make safely.
