# The runtime mutex locks through const

* Status: accepted
* Deciders: project owner
* Date: 2026-11-06

Technical Story: SonarQube Cloud rule `cpp:S8379` on `HomeserverRuntime::mutex`.

## Context and Problem Statement

`HomeserverRuntime::mutex` was a public `mutable RuntimeMutex` so that readers holding a `HomeserverRuntime const&`
could still lock it. Static analysis cannot tell that a public `mutable` member is a lock, and the member was open to
any mutation by any caller. How should a const reader lock the runtime mutex without a `mutable` member?

## Considered Options

* Keep `mutable RuntimeMutex mutex`.
* Make the member private behind an accessor.
* Make `RuntimeMutex::lock()`, `try_lock()` and `unlock()` `const`, keep the mutex's own state `mutable` inside
  `RuntimeMutex`, and hold it as a plain member.

## Decision Outcome

Chosen option: the third. `RuntimeMutex`'s lock functions are `const` and its `mutex_`, `owner_` and `depth_` are
`mutable`, so `HomeserverRuntime` holds it as a plain member and a `HomeserverRuntime const&` can still lock it. Every
lock is a `homeserver::RuntimeLock`, an alias for `std::unique_lock<RuntimeMutex const>`.

### Negative Consequences

* Code that spells `std::unique_lock<RuntimeMutex>` no longer matches `RequestLockScope` and `RuntimeLockRelease`; use
  `RuntimeLock`.

## Pros and Cons of the Options

### Keep `mutable RuntimeMutex mutex`

* Good, because it works unchanged.
* Bad, because a public mutable member is open to any mutation and static analysis cannot tell it is a lock.

### Private member with an accessor

* Bad, because it touches hundreds of call sites for no safety gain.

### Const lock functions

* Good, because the mutability is confined to the lock's own state, where it belongs.
* Good, because call sites change only in the spelling of the lock type.

## Links

* Refines [ADR-0004](0004-release-the-runtime-lock-through-the-mutex-not-a-guard.md)
