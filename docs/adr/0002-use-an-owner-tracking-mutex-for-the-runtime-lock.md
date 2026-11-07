# Use an owner-tracking mutex for the runtime lock

* Status: accepted
* Date: 2026-09-06

Technical Story: [#487](https://github.com/OMG-Software/Merovingian/issues/487)
· [PR #490](https://github.com/OMG-Software/Merovingian/pull/490)

## Context and Problem Statement

`HomeserverRuntime::mutex` is recursive so that self-locking service functions
(`create_room`, `join_room`, `leave_room`, `invite_user_by_threepid`) stay
independently callable. A release scope around a blocking network call must
therefore drop *every* level the calling thread holds; dropping one leaves the
mutex locked for the whole of the "released" call, and every other client
request and inbound federation transaction stalls behind it.

That defect shipped three times — 0.12.1, 0.12.3 and 0.12.6. `std::recursive_mutex`
cannot report whether the calling thread owns it, so a release scope had no way
to know whether it had actually released anything. How can the release scope
find out?

## Decision Drivers

* The defect was reaching production faster than review was catching it.
* An unprivileged authenticated client can trigger each instance: create a
  room, leave a room, or invite an address through a trusted identity server.
* Whatever is chosen must fail *closed* — prevention, not detection on a path
  a test happens to exercise.

## Considered Options

* Wrap `std::recursive_mutex` in a type that records its owner and depth
* Keep `std::recursive_mutex` and audit each call site
* Add a debug assertion that fails loudly when a release leaves the mutex held
* Maintain a `thread_local` recursion counter inside the release primitive

## Decision Outcome

Chosen option: "Wrap `std::recursive_mutex` in a type that records its owner
and depth", because it is the only option that lets a release scope ask a
question it can act on — `held_by_current_thread()` — rather than one a
reviewer has to answer by hand for every future call site.

`homeserver::RuntimeMutex`
([`runtime_mutex.hpp`](../../include/merovingian/homeserver/RuntimeMutex.hpp))
holds the owning thread id in an atomic and the recursion depth under the mutex
itself. It satisfies `Lockable`, so `std::unique_lock`, `std::lock_guard` and
`std::scoped_lock` work on it unchanged.

### Positive Consequences

* [ADR-0003](0003-drain-every-recursion-level-in-one-release-primitive.md)
  becomes possible: a release scope can drain until the thread genuinely holds
  nothing.
* Sites using CTAD (`std::unique_lock{runtime.mutex}`) needed no change at all.

### Negative Consequences

* 37 explicit `std::unique_lock<std::recursive_mutex>` spellings had to become
  `std::unique_lock<RuntimeMutex>`.
* Every acquisition pays one atomic store. The cost was not separable from
  noise in the existing lock soak harness
  (`tests/integration/test_runtime_lock_soak_flow.cpp`).
* `FederationRuntimeState::mutex` is a *different* mutex and was deliberately
  left as `std::recursive_mutex`. It has no release-scope problem, and changing
  it would have widened the diff for nothing — at the cost of two similar
  mutexes now having different types.

## Pros and Cons of the Options

### Wrap `std::recursive_mutex` in a type that records its owner and depth

* Good, because the release primitive can verify reality instead of trusting a
  guard's bookkeeping.
* Good, because it is a strict superset of `std::recursive_mutex`'s interface,
  so the migration is mechanical.
* Bad, because it introduces a project-specific lock type that a reader must
  learn.

### Keep `std::recursive_mutex` and audit each call site

* Bad, because two audits had already missed instances. The second missed one
  that had been *documented as fixed* — the 0.12.3 `leave_room` case.
* Bad, because it scales with every future caller of every self-locking
  function, forever.

### Add a debug assertion that fails loudly when a release leaves the mutex held

Suggested in [#487](https://github.com/OMG-Software/Merovingian/issues/487).

* Good, because it is cheap and localised.
* Bad, because it detects rather than prevents, and only on a path some test
  exercises. Every one of the three shipped instances passed the suite that
  existed when it shipped.
* Bad, because it needs the same ownership query this option provides —
  `std::recursive_mutex` cannot answer it either.

### Maintain a `thread_local` recursion counter inside the release primitive

* Bad, because the primitive does not observe acquisitions taken anywhere else,
  so the count would be wrong in exactly the nested case that matters.

## Links

* Enables [ADR-0003](0003-drain-every-recursion-level-in-one-release-primitive.md)
* Context in [`docs/http-transport.md`](../http-transport.md), "One release
  primitive, and why it drains every level"
