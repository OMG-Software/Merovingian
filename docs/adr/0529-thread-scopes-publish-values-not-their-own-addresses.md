# Thread scopes publish values, not their own addresses

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-06

Technical Story: PR #563's CodeQL check counted every open `cpp/stack-address-escape` warning on `main`

## Context and Problem Statement

Three RAII types publish something on the calling thread so code deeper in the call stack can read it without it being
passed through every signature: `observability::CorrelationScope`, `homeserver::RemoteMediaFetchScope` and
`homeserver::RequestLockScope`. Each stored an address in a `thread_local` pointer: the scope's own `this`, or the
address of the caller's `std::unique_lock`. Both are local variables, so CodeQL reports a stack address stored in
non-local memory (`cpp/stack-address-escape`, a warning, which the `main` ruleset's code-scanning rule treats as
blocking). The stores are correct while scopes nest, but that rests on an argument the types cannot state.

ADR-0526 settled `CorrelationScope` by holding the context by value. What should the other scopes publish, and what of
the fourth alert, the thread's audit database?

## Considered Options

* Publish values the scope owns, or an object that outlives every scope, instead of a scope's or a guard's address
* Dismiss the alerts as safe by nesting
* Allocate the published state on the heap

## Decision Outcome

Chosen option: "Publish values, or an object that outlives every scope".

* `RemoteMediaFetchScope`: the thread's slot holds the innermost scope's mode and deferral flag by value
  (`std::optional` of a file-local struct), and each scope keeps the values it displaced and puts them back when it
  closes. `deferred()` reads the slot, so its owner reads it while the scope is the innermost, as the one caller in
  `ClientServerRuntime.cpp` does once the calls it made have returned.
* `RequestLockScope`: the slot holds the `RuntimeMutex` the guard locks, not the guard. `RuntimeLockRelease` only ever
  asked a guard which mutex it refers to, and the mutex outlives every guard on it. No published guard is moved or
  released (`unique_lock::release`), so the mutex read at publication is the one the guard still refers to. If a future
  change moves a published guard, the published mutex is still the right one to release.

Rules for future code: a thread-local "current context" holds a value, or a pointer to an object that outlives every
scope on the thread. It never holds the address of a scope object or of a caller's local.

The thread's audit database (`install_local_audit_database`, `LocalDatabaseScope`) is the exception. The database is
owned by `HomeserverRuntime` and cannot be held by value, and a wrapper would only hide the pointer from CodeQL. Its
alert was dismissed on GitHub as "won't fix" with that reason (owner decision, 2026-11-06). The pointer is borrowed for
the life of a `LocalDatabaseScope`, which restores the previous value, or set once at start-up to the runtime's
database.

### Positive Consequences

* The slots no longer depend on a scope or guard object staying alive.
* The alerts are gone because the code changed.

### Negative Consequences

* `RemoteMediaFetchScope::deferred()` answers for the innermost scope, not for the object it is called on, so it must
  not be read while an inner scope is open.

## Pros and Cons of the Options

### Dismiss the alerts as safe by nesting

* Good, because nothing changes.
* Bad, because the safety rests on every scope closing in order, which the types cannot enforce.

### Allocate the published state on the heap

* Good, because the published address is not on a stack.
* Bad, because every request pays an allocation for a mode, a flag or one pointer the slot can hold itself.

## Links

* Extends [ADR-0526](0526-the-correlation-slot-holds-the-context-by-value.md)
