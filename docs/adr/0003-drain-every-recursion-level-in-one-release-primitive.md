# Drain every recursion level in one release primitive

* Status: accepted
* Date: 2026-09-06

Technical Story: [#487](https://github.com/OMG-Software/Merovingian/issues/487)
· [PR #490](https://github.com/OMG-Software/Merovingian/pull/490)

## Context and Problem Statement

Two primitives existed for releasing `runtime.mutex` around a blocking call.
`NetworkIoUnlock` acted on the thread's *published* guard (`RequestLockScope`);
`ScopedGuardRelease` acted on a guard *in hand*. At a nested call site those are
different objects, and picking the wrong one produced code that compiled,
passed its tests, and held a global mutex across a network round trip.

That distinction is precisely what made the 0.12.3 `leave_room` fix incomplete:
the callee released its own guard correctly while the dispatcher's stayed held.
How should a caller be prevented from getting this wrong?

## Decision Drivers

* Anyone reaching for "the release primitive" must get correct behaviour
  without first reasoning about which guard is which.
* The 0.12.1 and 0.12.3 fixes both worked by releasing at the *call site*,
  which leaves correctness depending on every future caller remembering to.

## Considered Options

* One primitive that releases every recursion level the calling thread holds
* Keep both primitives and document the difference more clearly
* Fix the third instance (`invite_user_by_threepid`) at its call site, as the
  first two were fixed

## Decision Outcome

Chosen option: "One primitive that releases every recursion level the calling
thread holds", because it removes the choice that was itself the bug source.

`homeserver::RuntimeLockRelease`
([`request_lock.hpp`](../../include/merovingian/homeserver/RuntimeLockRelease.hpp))
has two constructors, and they say only which `std::unique_lock` to read the
mutex address from:

```cpp
auto const released = RuntimeLockRelease{};        // the thread's published guard
auto const released = RuntimeLockRelease{guard};   // a guard in hand
```

Both release every recursion level the thread holds and restore exactly that
many on scope exit, throwing paths included. Choosing the "wrong" constructor
can no longer leave the mutex held.

### Positive Consequences

* Caller-side releases before delegating to a self-locking function are now
  redundant. The existing ones are kept because they are explicit, not because
  correctness depends on them.
* Enables [ADR-0005](0005-open-the-lock-release-scope-at-the-blocking-callee.md):
  the scope can move to where the blocking call is.

### Negative Consequences

* **Behaviour change.** A caller holding the mutex across a broader critical
  section now has it dropped by a callee's release scope. The only site where
  that could matter is `ingest_pdu_event`'s backend commit; both of its callers
  — the IPC handler-pool task in `worker_pool.cpp`, and
  `handle_federation_http_request` — reach it holding no level, so it is a
  no-op there. **A new caller of `ingest_pdu_event` that holds `runtime.mutex`
  reopens this question**, and is the thing to check before adding one.
* **A gap, stated so it is not mistaken for coverage.** The default-constructed
  `RuntimeLockRelease{}` does nothing when a caller holds the mutex without
  publishing a `RequestLockScope`, because it has no way to find the mutex.
  Pass the guard in that case.
* The `NetworkIoUnlock` and `ScopedGuardRelease` names disappear from the tree,
  so older commit messages and review threads refer to types that no longer
  exist.

## Pros and Cons of the Options

### One primitive that releases every recursion level

* Good, because the failure mode is structurally unreachable rather than
  documented.
* Good, because it composes: a nested scope finds nothing left to release and
  correctly does nothing.
* Bad, because it releases locks its immediate caller did not take, which is
  surprising until the recursion is understood — hence this record.

### Keep both primitives and document the difference more clearly

* Bad, because the difference *was* already documented when `leave_room` was
  got wrong. The header comment on `ScopedGuardRelease` said exactly which
  guard it acted on, and that did not prevent the defect.

### Fix the third instance at its call site

* Good, because it is the smallest possible change.
* Bad, because it fixes one instance of a class that had already produced three
  and would keep producing more.

## Links

* Requires [ADR-0002](0002-use-an-owner-tracking-mutex-for-the-runtime-lock.md)
* Refined by [ADR-0004](0004-release-the-runtime-lock-through-the-mutex-not-a-guard.md)
