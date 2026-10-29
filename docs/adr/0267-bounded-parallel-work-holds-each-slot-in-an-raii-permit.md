# Bounded parallel work holds each slot in an RAII permit

* Status: accepted
* Date: 2026-10-29

Technical Story: SonarQube Cloud rule `cpp:S8460` on `src/homeserver/room_service.cpp`, triaged 2026-10-29

## Context and Problem Statement

Three places fan work out over `std::async` with a counting semaphore capping how many run at
once: the inbound transaction's sender-key prepass (`inbound_request.cpp`), the `send_join` state
key resolution (`room_service.cpp`) and the make_join race. Each file carried its own copy of
`PortableSemaphore`, and each released its slot differently. The sender-key prepass moved a
permit onto the task's stack; the make_join race used a local destructor struct; the `send_join`
loop called `sem.release()` as the last line of the task. `resolve_join_state_key` can throw, and
a task that throws skips that line: after `parallelism` such throws every slot is gone, the loop's
next `acquire()` waits forever, and the join request and its thread hang. How should bounded
parallel work take and return its slots?

## Considered Options

* One shared runner, `core::run_bounded_parallel`, whose tasks hold their slot in a
  `core::SemaphorePermit`
* Fix the one loop with a `try`/`catch` around the task body
* `std::counting_semaphore`

## Decision Outcome

Chosen option: "One shared runner whose tasks hold their slot in a `core::SemaphorePermit`",
because the slot is then returned by a destructor on every exit (return, throw, or a task
`std::async` failed to launch), and the loop that gets this right is written once.

`core::PortableSemaphore` and `core::SemaphorePermit` (`core/portable_semaphore.hpp`) replace the
per-file copies. `core::run_bounded_parallel(count, parallelism, task)`
(`core/bounded_parallel.hpp`) runs `task(i)` for each index with at most `parallelism` at once,
treats a parallelism of 0 as 1, joins every task before returning, and then rethrows the
lowest-indexed task's exception, so nothing still running can touch state the caller is
unwinding. Both key-resolution loops use it. The make_join race keeps its own loop, since its
futures outlive the call (orphaned once a winner is found), but holds its slot in a
`SemaphorePermit`.

New code that caps parallel work uses `run_bounded_parallel`, or, when its tasks must outlive the
call, a `SemaphorePermit` taken right after `acquire()`. A slot is never released by hand.

### Positive Consequences

* A throwing task can no longer starve the rest of the batch, and the behaviour is unit-tested
  once (`tests/unit/test_bounded_parallel.cpp`, `[core][bounded_parallel]`).

### Negative Consequences

* The sender-key prepass now captures its resolver by reference instead of copying it into each
  task. That is safe only because the runner joins every task before returning.

## Pros and Cons of the Options

### Fix the one loop with a `try`/`catch` around the task body

* Good, because it is a one-line change.
* Bad, because it leaves three copies of the pattern, and a slot is still lost if `std::async`
  throws after `acquire()`.

### `std::counting_semaphore`

* Bad, because NetBSD's libc++ does not provide it, which is why `PortableSemaphore` exists.
