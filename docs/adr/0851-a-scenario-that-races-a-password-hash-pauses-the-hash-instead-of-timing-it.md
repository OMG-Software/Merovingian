# A scenario that races a password hash pauses the hash instead of timing it

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

Several AUTH-4 scenarios prove what happens when another request lands while a password is hashing. They prove that a
logout revokes the session before a password change commits, that a competing change is not overwritten, and that
registration does not hold `runtime.mutex` across Argon2id. Production hashes only inside a `RuntimeLockRelease` scope,
so the race is real. ADR-0510 had these scenarios hold `RealPasswordHashCost`, so the hash takes the roughly 100 ms of
the interactive cost, and hope the main thread takes the lock inside that window.

On a loaded ThreadSanitizer runner it did not. The logout scenario saw its device deleted after the change had already
committed, so `change.ok` was true and the suite failed. It was not testing what it claims, and a passing run gave no
evidence that the race was exercised. Its two siblings detect a lost race with `REQUIRE(overlapped)`, but they still
fail when it happens.

How does a scenario make its competing request land inside the hash every time?

## Considered Options

* Keep the real cost and assert the overlap (ADR-0510 as written)
* Make the real hash slower, or retry the scenario
* A test seam in production code that runs a callback while the lock is released
* Pause the hash in the test binaries' existing `crypto_pwhash_str` wrapper

## Decision Outcome

Chosen option: "Pause the hash in the test binaries' existing `crypto_pwhash_str` wrapper", because it makes the
overlap certain without adding anything to production code.

`tests/support/PasswordHashPause` is armed by constructing it. The next `crypto_pwhash_str` call on any thread, routed
through the wrapper of ADR-0510, stops until `release()` or the pause's destruction. A scenario:

1. arms the pause after its setup has hashed what it needs;
2. starts the request under test on a worker thread;
3. waits with `wait_until_hashing(timeout)` and requires that it returned true;
4. makes its competing request under `runtime.mutex`;
5. releases the pause and joins the worker.

The worker is declared before the pause, so on any early exit the pause is destroyed (released) before the thread is
joined. Such a scenario hashes at the minimum cost and does not hold `RealPasswordHashCost`.

ADR-0510's minimum-cost wrapper is unchanged. Its rule that a racing scenario holds `RealPasswordHashCost` is
superseded for races against `crypto_pwhash_str`.

### Positive Consequences

* The race is exercised on every run, under any load and any sanitizer, and a scenario that cannot reach the hash fails
  with `REQUIRE(hashing)` instead of passing vacuously.
* The scenarios no longer pay the real Argon2id cost.

### Negative Consequences

* The wrapper wraps only `crypto_pwhash_str`. A scenario that races password verification
  (`crypto_pwhash_str_verify`), such as the user-interactive-auth check, still relies on `RealPasswordHashCost` and
  timing.
* The pause is process-wide. A scenario must not arm it while unrelated threads may hash, or one of those would stop
  instead.

## Pros and Cons of the Options

### Keep the real cost and assert the overlap

* Good, because nothing changes.
* Bad, because about 100 ms is not a guarantee: a scheduler or a sanitizer can delay the main thread past it, as the
  `tsan` job showed.

### Make the real hash slower, or retry the scenario

* Good, because it is quick to write.
* Bad, because a longer window only makes the failure rarer, and a retry hides it. Both add run time.

### A test seam in production code

* Good, because it could pause any lock release, verification included.
* Bad, because it adds a hook to the authentication path that production must never trigger. The wrapper already
  exists only in the test binaries.
