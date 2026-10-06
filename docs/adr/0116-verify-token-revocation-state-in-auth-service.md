# Verify token revocation state in the auth service

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-06

Technical Story: 2026-09-29 security audit, finding DB-5.

## Context and Problem Statement

The `database::revoke_*` helpers return the number of in-memory rows they
updated. That count equals the number of durable rows written only when the
backend commit succeeds. A persistence failure also returns `0`, which is the
same answer as "no rows matched the query". The auth service previously treated
a zero count as success in several logout/deactivation/password-change/device-
deletion paths, so a failed durable write would silently leave active tokens in
the store. The audit required every token revocation path to fail closed on a
database write failure.

## Decision Drivers

* Fail-closed security: a client that receives a 200 for logout/password change
  must be able to trust that the targeted tokens are unusable.
* No false positives: an account with no refresh tokens must not fail because the
  refresh-token revocation naturally updates zero rows.
* Testability: unit tests need a way to make a specific revocation statement fail
  without disturbing the unrelated password/device updates that happen in the
  same call path.

## Considered Options

1. Change every `revoke_*` helper to return a `bool` (`true` == commit
   succeeded) and reject on `false`.
2. Keep the `std::size_t` return value and add a persistent-store state
   verification helper for each revocation scope used by the auth service.
3. Add a dedicated "commit succeeded" out-parameter to the helpers.

## Decision Outcome

Chosen option: "keep the count and verify persistent-store state", because it
preserves the existing public API (the count is still useful for metrics and
audit logs) while making the actual security decision depend on the durable
state, not on an ambiguous number. Each auth-service path now checks a small
helper that answers "are all targeted rows actually revoked?" and returns 500 if
any unrevoked token remains.

A test-only seam was added to the memory backend so a unit test can name the
statement that must fail. This avoids the earlier `force_next_persist_failures`
blunt instrument, which could not target a revocation statement that runs after
an unrelated write in the same path.

### Positive Consequences

* Logout, device deletion, password change, deactivation and token refresh all
  return 500 when the revocation write fails, preventing a false "success".
* The count remains available for diagnostics.
* Unit tests can cover each revocation scope independently.

### Negative Consequences

* Each revocation path performs an extra linear scan over the relevant token
  vector. Token vectors are per-user in scope, so the cost is small and bounded
  compared to the database write.
* The test-only failure seam is present in `PersistentStore`; it is guarded by
  documentation and only honoured by the memory backend, but it is one more
  branch to reason about.

## Pros and Cons of the Options

### Return `bool` from revocation helpers

* Good, because it directly exposes commit success to every caller.
* Bad, because it breaks the existing API and loses the count for callers that
  want it.
* Bad, because it still requires callers to know which tokens should exist; a
  count of zero with no matching rows is safe, while a count of zero with
  matching rows is not.

### Verify persistent-store state

* Good, because the security decision is based on the actual token state, not an
  ambiguous count.
* Good, because the API is unchanged.
* Bad, because it adds a small extra scan per revocation path.

### Add a commit out-parameter

* Good, because it preserves both the count and explicit success information.
* Bad, because it complicates every helper signature and every caller for a
  concern that can be answered by checking the store state directly.
