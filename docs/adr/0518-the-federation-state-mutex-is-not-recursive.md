# The federation state mutex is not recursive

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

## Context and Problem Statement

`FederationRuntimeState::mutex` was a `std::recursive_mutex` (`cpp:S8462`). The only place one thread locked it twice was
`record_completed_federation_transaction`, which held `federation_guard` and then called
`federation_transaction_completed`, which took the guard again. Should the mutex stay recursive?

## Considered Options

* Keep `std::recursive_mutex`.
* Remove the double lock and use a plain mutex.

## Decision Outcome

Chosen option: "Remove the double lock and use a plain mutex". The lookup moved into an anonymous-namespace helper,
`completed_answer_with_guard_held`, that expects the guard to be held; the recording function calls it directly. Every
other function that takes the guard releases it before calling another that does.

## Pros and Cons of the Options

### Keep std::recursive_mutex

* Bad, because it hides re-entry into half-updated state: the inner call sees an invariant the outer call has not yet restored.
* Bad, because a condition-variable wait releases only one recursion level, so a caller holding the lock twice would sleep
  with the lock still held and block every thread that needs it.

### Plain mutex

* Good, because a second lock by the same thread is a deadlock a test finds, not silent re-entry.
* Bad, because new code must add a lock-held helper instead of calling a guard-taking function; the federation guidance says so.

## Links

* Builds on [ADR-0517](0517-guarded-value-types-hold-their-mutex-by-value.md)
