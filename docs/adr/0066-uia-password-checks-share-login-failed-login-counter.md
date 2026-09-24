# UI-auth password checks share the `/login` failed-login counter

* Status: accepted
* Date: 2026-09-24

## Context and Problem Statement

The 0.12.13 security audit found that `verify_local_user_password` — the
helper used by every UI-Auth (UIA) `m.login.password` stage — checked the
password hash without consulting the per-account failed-login throttle that
`/login` uses. An attacker who had already stolen an access token could
therefore brute-force the account password through password change,
deactivation, 3PID add, cross-signing upload, and device-deletion endpoints,
getting a fresh, unbounded guessing budget instead of the five-attempt
budget that `/login` enforces.

## Decision Drivers

* A password check is a password check: the account lockout must protect the
  password wherever it is exercised, not only on the login endpoint.
* The existing `/login` counter is keyed on the claimed/authenticated user ID
  and stored in memory with a 15-minute window and lockout.
* UIA call sites return `401` challenges, but a rate-limit condition must still
  be visible to the client as `429 M_LIMIT_EXCEEDED` per the Client-Server
  API.

## Considered Options

1. **Share the `/login` counter.** Reuse `failed_login_lockout_remaining_ms`,
   `record_failed_login`, and `clear_failed_logins` inside
   `verify_local_user_password`.
2. **Maintain a separate UIA counter.** Track failures from UIA stages in a
   second map with its own threshold.
3. **Leave UIA unthrottled.** Rely on access-token possession as sufficient
   authentication.

## Decision Outcome

Chosen option: **share the `/login` counter**, because it gives the password
exactly one guessing budget across every endpoint that exercises it. A stolen
token does not downgrade the account's brute-force resistance; the same
five-failure threshold and fifteen-minute lockout apply everywhere.

`verify_local_user_password` now returns `PasswordVerificationResult`
containing `ok` and `retry_after_ms`. It checks the lockout before hashing,
records a failure after a wrong password, and clears the history on success.
Each UIA call site in `src/homeserver/client_server.cpp` translates a
non-zero `retry_after_ms` into `429 M_LIMIT_EXCEEDED` with a `Retry-After`
header.

### Positive Consequences

* A single, auditable lockout policy covers all password verification paths.
* No new persistence or configuration is needed; the existing in-memory counter
  already has the right window/lockout semantics.
* The UIA response remains spec-conformant (`429` with `retry_after_ms`).

### Negative Consequences

* A legitimate user who forgets their password can now be locked out of UIA
  operations, not just `/login`. Any successful password entry clears the
  counter, so the impact is bounded.
* The compile-time thresholds remain shared; operators cannot tune `/login`
  and UIA separately, which is acceptable because the asset being protected
  is the same password.

## Pros and Cons of the Options

### Share the `/login` counter

* Good, because it closes the bypass with no new state machinery.
* Good, because an attacker cannot choose the weaker of two throttles.
* Bad, because it couples the UIA experience to the login throttle
  constants, but those constants protect the same credential.

### Separate UIA counter

* Good, because UIA failures would not affect `/login` availability.
* Bad, because it creates a second code path and a second budget that an
  attacker can exhaust independently, doubling the effective guesses.
* Bad, because it requires new state, tests, and operational understanding.

### Leave UIA unthrottled

* Good, because it avoids any change to the UIA flow.
* Bad, because a stolen token gives unlimited password guesses, which is the
  exact vulnerability the audit identified.

## Links

* Refines [ADR-0032](0032-throttle-failed-logins-per-claimed-account.md) — the
  original `/login` throttle decision now also governs UIA password checks.
* See `docs/auth-identity.md` — "Per-account failed-login throttle".
* See `CHANGELOG.md` 0.12.13 — M-02 entry.
