# Delete the device row after its tokens are revoked

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, finding F-67.

## Context and Problem Statement

`delete_local_device` deleted the device row first, in a transaction of its own,
and revoked the device's access and refresh tokens in two further commits. The
database layer reports a missing row as `false`, so a later call found no row and
answered `404 M_NOT_FOUND` before reaching the revocations. When a revocation
commit failed after the row was gone, the call answered 500 and the device's
access token stayed live. Nothing could revoke it afterwards: a retry of
`DELETE /devices/{deviceId}` answered 404, and `POST /delete_devices` treats 404
as "already gone" and answered 200 over a live token. A non-refresh login has no
expiry. `logout_local_user` had the mirror fault: it marked the in-memory session
revoked before the persists, so a persistence failure left a retry answered as
unauthenticated while the refresh token it had not yet revoked could still mint.

Which step of a multi-commit operation should be the retry gate?

## Decision Drivers

* ADR-0116: a client that receives success must be able to trust the targeted
  tokens are unusable.
* The operation spans several commits with no enclosing transaction.
* A retry must be able to finish what a failure left undone.

## Considered Options

* Revoke first, verify against the store, mark sessions, answer 404 if there was
  no device row, delete the row last (the order `logout_all_local_user` uses)
* Keep the row delete first and make the revocations run on a 404 as well
* Put the row delete and the token revocations into one transaction

## Decision Outcome

Chosen option: "revoke first and delete the row last". The row delete is the
only step whose repeat is answered differently (404), so it must be the last
irreversible step and never the gate to the others. A failure at any step leaves
the device present, and a retry repeats the revocations (idempotent) before it
reaches the delete. A call for a device that is gone still revokes tokens that
an earlier failure stranded, then answers 404; it writes nothing when no token is
live. In `logout_local_user`, `session.revoked` is set only after the persists
succeed, so the session stays usable for the retry.

The rule for future code: in an operation made of several commits, the step that a
repeat reports as "already done" is performed last, and in-memory state that
authenticates a caller is changed only after the durable writes it mirrors.

### Negative Consequences

* A device deletion makes up to two more writes than before when tokens are live.
* After a failure that revoked the access token in the store but not the refresh
  token, the in-memory session still authenticates until the retry or a restart.
  The client was told 500 and retries; this is the price of keeping the retry
  possible.

## Pros and Cons of the Options

### Revoke first, delete the row last

* Good, because every failure is retryable and a retry converges.
* Good, because it is the order the neighbouring `logout_all_local_user` already
  follows.
* Bad, because the durable state is briefly inconsistent (tokens revoked, device
  listed) after a failure.

### Delete first and revoke on 404

* Good, because the row delete keeps its position.
* Bad, because every 404 path would then have to be understood as "maybe revoke",
  which is the coupling that caused the defect.

### One transaction

* Good, because the operation becomes atomic.
* Bad, because the revocation helpers each own their transaction and mirror
  update; merging them is a larger change to the persistence layer than the
  defect needs.

## Links

* Refines [ADR-0116](0116-verify-token-revocation-state-in-auth-service.md)
