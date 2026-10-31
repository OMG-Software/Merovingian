# The dispatch worker sets its shutdown flag under its mutex

* Status: accepted
* Date: 2026-10-31

Technical Story: SonarQube Cloud finding on `src/federation/dispatch_worker.cpp` (use
`std::memory_order::seq_cst`), 0.12.65.

## Context and Problem Statement

`DispatchWorker`'s idle wait is `cv_.wait_for(lock, idle_poll, predicate)`, and the predicate reads
`shutdown_requested_`. `request_shutdown()` stored the flag with `memory_order_release` and called
`notify_all()` without taking `mutex_`. A store and notify that land after the predicate has read
`false` but before `wait_for` blocks wake nobody, so the worker slept for the whole `idle_poll`
before it saw the request. The `release`/`acquire` pair orders memory; it cannot stop that wake-up
being lost, and no memory order can. How does the flag reach a waiting worker every time?

## Considered Options

* Store the flag while holding `mutex_`, notify after releasing it, and use the default
  (sequentially consistent) memory order for every access to the flag.
* Keep the lock-free `release` store and `acquire` loads.
* Store the flag lock-free, then lock and unlock `mutex_` before notifying.

## Decision Outcome

Chosen option: store the flag under `mutex_`, with the default memory order. The predicate runs with
`mutex_` held, so the store happens either before the predicate (which then sees `true`) or after
`wait_for` has released the lock and is waiting (which then gets the notify). The flag stays atomic
because the loop also reads it outside the lock. Every access uses the default order: nothing
here is hot enough for a weaker order to matter, and one rule for the whole flag is easier to
check than a mix of orders.

### Positive Consequences

* A shutdown request always wakes an idle worker at once. The unit scenario tagged
  `[shutdown-wakeup]` requests shutdown from inside the wait predicate, the window that lost it.

### Negative Consequences

* `request_shutdown()` (`noexcept`) locks a `std::mutex`. A `lock()` that throws would end the
  process. `summary()` (`noexcept`) already does the same.

## Pros and Cons of the Options

### Keep the lock-free `release` store and `acquire` loads

* Good, because `request_shutdown()` never blocks.
* Bad, because a request that lands between the predicate and the block is lost until `idle_poll`
  runs out. This is the defect, and the weaker order looks like an optimisation of the chosen
  option, not the bug.

### Store lock-free, then lock and unlock `mutex_` before notifying

* Good, because it closes the window too.
* Bad, because an empty lock section looks like dead code and invites removal.

## Links

* Related to [ADR-0309](0309-a-federation-retry-waits-from-the-end-of-the-failed-attempt.md), which made the idle wait wake for a due transaction instead of a non-empty queue
