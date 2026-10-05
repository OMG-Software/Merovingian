# Re-verify the user and password hash after Argon2id

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-10-05

Technical Story: security audit finding on `fix/audit-medium-0.12.16`

## Context and Problem Statement

`POST /_matrix/client/v3/login` releases `runtime.mutex` around the Argon2id
password verification so that one slow login cannot stall every other request.
Before releasing, it snapshots the claimed `user_id` and the `password_hash` to
verify against. A concurrent password change can persist a new hash while that
verification runs. The original implementation then re-acquired the lock and
issued a session based on the old hash, so a password invalidated mid-login
remained usable until the session was minted.

## Decision Drivers

* An attacker who knows the old password must not be able to keep a login in
  flight across a password change and obtain a fresh session.
* The fix must preserve the AUTH-4 invariant that Argon2id never runs while
  holding `runtime.mutex`.
* The fix must not hold a pointer into `runtime.database.users` across the lock
  release, because the vector may reallocate.

## Considered Options

1. **Snapshot only the password hash (status quo).** Simple and fast, but fails
   the security requirement because the hash can change while Argon2id runs.
2. **Snapshot the hash, then re-find the user and compare the current hash after
   re-acquiring the lock.** Adds one extra hash comparison and a second user
   lookup; meets the requirement without re-running Argon2id.
3. **Hold `runtime.mutex` across Argon2id.** Would serialize all login attempts
   and every other request behind a slow password hash, violating AUTH-4.

## Decision Outcome

Chosen option: **option 2**. After the unlocked Argon2id verification succeeds,
`login_local_user` re-finds the user by the snapshot `user_id` and rejects the
login if the user is gone or the stored `password_hash` no longer matches the
hash that was verified. This closes the race without changing the locking model.

### Positive Consequences

* A password invalidated during login verification cannot issue a session.
* A user deleted or deactivated during verification is also rejected, closing
  the same class of TOCTOU race for account lifecycle changes.
* No additional Argon2id work is performed; the only new cost is a string
  comparison and a second vector lookup.

### Negative Consequences

* A legitimate but slow login can still race against a concurrent password
  change and fail, even though the old password was correct at the moment the
  verification started. This is the intended security trade-off.
* The comparison uses the stored hash string; if the hash representation ever
  gains a canonicalisation issue, the comparison must account for it.

## Links

* `src/homeserver/auth_service.cpp` — `login_local_user`
* `tests/integration/test_security_audit_login_snapshot_flow.cpp`
* Relates to ADR-0090 (Bound Argon2id work with a process-wide admission semaphore)
