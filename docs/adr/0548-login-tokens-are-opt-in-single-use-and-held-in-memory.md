# Login tokens are opt-in, single-use, held in memory and always ask for the password

* Status: accepted
* Date: 2026-11-07

Technical Story: CS8, `POST /_matrix/client/v1/login/get_token`, the `m.login.token` login, `GET /admin/whois/{userId}`.

## Context and Problem Statement

`POST /login/get_token` is optional in the spec (v1.7). A login token hands a full session, with a new device, to
whoever holds it. How should this server offer it, and where does it keep the tokens?

## Considered Options

* On by default, tokens in a new database table.
* Off by default behind `security.login_token.enabled`, tokens in memory only.
* Reuse the persisted `login_tokens` table that SSO uses.

## Decision Outcome

Chosen option: "off by default, in memory only", because an operator should opt in to a feature that mints
session-equivalent credentials, and a token that lives two minutes does not need to survive a restart.

* Off: `get_token` is `404 M_UNRECOGNIZED` (also before authentication, as for any route not served), `GET /login`
  offers no `m.login.token` flow, `m.get_login_token` reports `enabled: false`. SSO login tokens are a separate
  feature and keep working.
* `get_token` runs UIA with `m.login.password` on every call. A UIA session id proves nothing (the password travels in
  the `auth` block), so there is nothing to reuse; the spec's "MUST always re-prompt" holds because every call needs
  the password. The password check is the existing `verify_local_user_password` (Argon2id admission, its own throttle).
* The token is 256 bits from libsodium, returned once, stored as an unkeyed BLAKE2b-256 hash in `LoginTokenStore`,
  compared with `constant_time_equal` over every entry, spent by the first `POST /login` that names it (success or
  not), valid 120000 ms. A restart drops unredeemed tokens (documented in the user manual).
* Bounded: 4 live tokens per user, 1024 in all; a request over either is `429 M_LIMIT_EXCEEDED` with `retry_after_ms`.
  Nothing is evicted, so a flood for one account cannot displace the tokens its owner just minted.
* Rate limit: a built-in per-user cap of 4 requests per 60 seconds on the route. The spec suggests 1 a minute, but a
  UIA flow is two requests (challenge, then password), so 1 would refuse every client's second step; 4 lets one flow
  and one retry through.
* `m.login.token` login uses `login_local_user_by_id`, the path SSO already uses, so the device creation, audit and the
  deactivated, locked and suspended refusals are the same as for a password login.
* whois returns only what the server holds: devices, each with one session whose `connections` is empty. The server
  records no IP, user agent or last-seen time and this feature does not start. A non-admin asking about anyone else is
  `403` before any lookup.

### Negative Consequences

* A restart invalidates tokens minted in the last two minutes; the client mints another.
* A per-user rate of 4 a minute is looser than the spec's suggested 1 a minute.

## Links

* [ADR-0057](0057-uiaa-sessions-are-in-memory-and-single-stage.md) is the neighbour for UIA state (in memory, single stage).
