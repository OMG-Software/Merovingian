# Login failures are throttled per source, with an account-wide ceiling

* Status: accepted
* Date: 2026-10-07

Technical Story: 29 September 2026 security audit, findings AUTH-2 (anyone can hold any
account in login lockout) and AUTH-10 (the failed-login map is unbounded and scanned on
every failure). Supersedes [ADR-0066](0066-uia-password-checks-share-login-failed-login-counter.md)
and refines [ADR-0032](0032-throttle-failed-logins-per-claimed-account.md).

## Context and Problem Statement

ADR-0032 throttled failed logins per claimed account: five failures refused every login
for that account for 15 minutes, correct passwords included. ADR-0066 made user-interactive
auth (UIA) password checks share that counter, so a thief holding an access token could not
brute-force the password through UIA instead.

Together they let anyone lock any account out, at a cost of five requests per 15 minutes,
and while locked the owner also could not change their password, deactivate or delete
devices through UIA. The counter map grew with every distinct claimed user ID and was
scanned in full on every failure.

How should password guessing be limited without letting a stranger lock an account out?

## Decision Drivers

* A stranger must not be able to stop the owner logging in from where the owner is.
* Guessing spread over many addresses must still be stopped.
* A thief holding a session must still not be able to brute-force the password via UIA
  (ADR-0066's goal).
* Unauthenticated failures must not block UIA from an already-authenticated device.
* Memory and per-failure work must be bounded whatever the claimed user IDs are.

## Considered Options

* **Per (account, source) counter, a per-account ceiling, and a separate UIA counter per
  (account, device) (chosen).**
* Per (account, source) only. Rejected: a botnet guesses at full speed, five attempts per
  address.
* Keep the per-account counter and only exempt UIA. Rejected: a stranger can still lock the
  owner out of logging in.

## Decision Outcome

Chosen option: per source, with a ceiling and a separate UIA counter.

* Login failures count in two tables: keyed on (account, client source), where the source is
  `rate_limit_client_key` (trusted proxies honoured, IPv6 grouped by prefix), and keyed on the
  account alone. `security.login_throttle.max_failures_per_source` (5) refuses that account's
  password logins from that source only; `max_failures_per_account` (50) refuses them from
  everywhere; both within `security.login_throttle.window` (15m). A refusal is
  `429 M_LIMIT_EXCEEDED` with `retry_after_ms`.
* A successful login clears only its source's counter. The ceiling is not cleared, or an
  attacker could spend 49 guesses, wait for the owner to log in, and start again.
* UIA password checks count in their own table keyed on (account, device), with the
  per-source threshold. Login failures never touch it and it does not feed the ceiling, so
  the owner's existing sessions keep working while the account is under attack, and a thief
  holding one session is still limited to a few guesses per window.
* Each table stores a fixed-size BLAKE2b digest of its key, holds at most 100,000 entries,
  and expires entries from a list ordered by window start, so every operation is amortised
  O(1) and nothing scans the table (`auth::FailureWindowTable`).
* `login.rejected` and `login.throttled` audit rows are rate-capped like other
  unauthenticated rejections (AUTH-1).

### Positive Consequences

* Locking an account out from everywhere takes 50 failures per window instead of 5, and
  never affects the owner's existing sessions.
* Bounded memory and work under a flood of distinct claimed user IDs.

### Negative Consequences

* Behind a reverse proxy without `server.trusted_proxies`, every client shares one source and
  the per-source counter degrades to per-account.
* The ceiling can still be reached deliberately; the owner then waits out the window or uses
  an existing session.
* More than 100,000 distinct keys inside one window evict the oldest counters early; the
  per-IP rate limit makes that expensive.
* Counters use fixed windows, so a burst straddling a window boundary can reach twice the
  threshold.
