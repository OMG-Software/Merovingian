# Throttle failed logins per claimed account

* Status: accepted; refined by [ADR-0122](0122-login-failures-are-throttled-per-source-with-an-account-ceiling.md) (2026-10-07)
* Date: 2026-09-06

## Context and Problem Statement

`/login` was throttled only per source IP, because the runtime rate limiter's
per-user tier keys on the *authenticated* user — who, before a login succeeds,
does not exist yet. Guesses against one account spread across many source IPs
therefore accumulated against nothing at all.

## Considered Options

* Track failures against the claimed user ID, whether or not that user exists
* Keep per-source-IP throttling only

## Decision Outcome

Chosen option: "Track failures against the claimed user ID, **whether or not
that user exists**". Counting only real accounts would turn the throttle itself
into an account-existence oracle.

### Negative Consequences

* **A third party can deliberately trip a real account's lockout** by guessing
  against it. That is accepted, bounded by a fixed short window and immediate
  clearing on a successful login — but it is a denial-of-service primitive, and
  lengthening the window would make it a worse one.
* Failure state is keyed on an attacker-supplied string, so the table must
  itself be bounded.

## Links

* [`docs/auth-identity.md`](../auth-identity.md), "Per-account failed-login throttle"

<!-- Backfilled in 0.12.6 from existing documentation and code. The date above is
the date of the record, not of the decision; the decision predates it. -->
