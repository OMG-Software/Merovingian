# Bound Argon2id work with a process-wide admission semaphore

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Argon2id password and registration-token verification is memory-hard and CPU-
intensive. The 2026-09-29 security audit (AUTH-4) found that running this work
under the global `HomeserverRuntime::mutex` lets a moderate volume of
unauthenticated login or token-validity requests serialise every other client
and federation request. Even after the lock was released around the libsodium
call, an attacker could still exhaust process memory bandwidth by starting an
unbounded number of concurrent hashes.

How do we limit concurrent Argon2id work without queuing more load once the
system is saturated?

## Decision Drivers

* Memory-hard hashing must not be a global lock multiplier or memory-bandwidth
  exhaustion vector.
* An unauthenticated endpoint cannot be allowed to queue arbitrary work; it must
  shed load when saturated.
* Shed load must not be treated as a failed authentication attempt, otherwise
  an overload attacker could also lock legitimate accounts out.
* The mechanism must be RAII-safe, exception-safe, and not introduce raw
  pointers or manual `new`/`delete`.

## Considered Options

1. **Bounded thread-pool for Argon2id calls.** Submit hash work to a thread pool
   with a fixed size and block the request thread until a slot is available.
2. **Counting semaphore with non-blocking `try_acquire` and 429 shedding.** Admit
   only a fixed number of in-flight hashes; excess requests fail immediately
   with HTTP 429 / `M_LIMIT_EXCEEDED`.
3. **Separate mutex-protected queue with a hard cap and synchronous execution on
   the caller's thread.** Serialize hashes through a queue whose size is capped,
   but still run them synchronously when a slot is taken.

## Decision Outcome

Chosen option: **option 2**, because it bounds memory and CPU pressure directly,
fails fast without blocking request threads, and maps cleanly to the Matrix
`M_LIMIT_EXCEEDED` error semantics. A thread pool (option 1) would still queue
work and could block request threads behind a full pool; option 3 adds queueing
complexity without a clear benefit over a semaphore.

`auth::Argon2idAdmission` wraps a `std::counting_semaphore` and returns an RAII
`auth::Argon2idSlot` on success. The slot is released automatically when it leaves
scope, including if the hash throws. One admission instance lives on
`HomeserverRuntime`, stored by `unique_ptr` so the runtime remains movable. The
default capacity is four concurrent operations; callers that need to test the
boundary can replace the pointer with a test-configured admission.

`/login`, `/register` (when token verification is required), and
`GET /_matrix/client/v1/register/m.login.registration_token/validity` acquire
a slot before running the Argon2id verification outside the runtime mutex. If
no slot is available they return 429 before any hash work is performed and do
not increment the per-account failed-login counter.

### Positive Consequences

* The global runtime mutex is never held during bounded Argon2id work.
* Saturation produces an explicit, client-actionable `M_LIMIT_EXCEEDED` rather
  than queueing or silently stalling.
* Legitimate accounts are not penalised for shed requests.
* The RAII slot makes it impossible to leak a permit on success, failure, or
  exception.

### Negative Consequences

* Capacity is currently fixed at compile-time defaults rather than dynamically
  tuned to host resources.
* A very small capacity could cause false-positive shedding on legitimate login
  bursts; the default of four was chosen to protect a typical single-server
  deployment while remaining generous enough for normal login rates.

## Links

* Security-audit tracking: [docs/todos/capability-gaps.md](../todos/capability-gaps.md)
* Related: [ADR-0032 - Throttle failed logins per claimed account](0032-throttle-failed-logins-per-claimed-account.md)
