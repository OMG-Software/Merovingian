# The account pages keep a fixed 15-minute session in memory, bound to a strict cookie and a form token

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 8 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md) (proposal P6)

## Context and Problem Statement

The spec puts all account management of an OAuth 2.0 user in the homeserver's web UI ("Account management"):
`account_management_uri` with the six `org.matrix.*` actions. The pages at `/_merovingian/account` let a user sign
out a device, change the password, deactivate the account and approve a cross-signing reset. Unlike the authorisation
pages (ADR-0787), they need to remember a signed-in user across a few page loads. How is that session held and how is a
form post tied to it?

## Decision Drivers

* A session that outlives its use is a standing credential in a browser.
* A form post must not be forgeable from another site, nor by one signed-in session for another.
* Nothing the session needs survives a restart, and nothing about it should be in the database.

## Considered Options

* A session in memory: 15 minutes from sign-in, never extended, under the hash of a 32-byte secret sent as a
  `__Host-mv-account` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `Max-Age=900`), with a form token derived from
  the secret.
* A database-backed session with a sliding expiry.
* No session: ask for the password on every action, as the authorisation pages do.

## Decision Outcome

Chosen option: the first.

* `AccountSessionStore` (`HomeserverRuntime::account_sessions`) holds a session under `oauth_secret_hash` of the
  secret; the secret is returned once and never kept. 4096 sessions in all, 4 per user: a fifth sign-in replaces the
  user's own oldest, a sign-in at the total cap is refused (503), never another user's session evicted. Expired
  sessions are purged at the start of every operation. Every call takes the time, so tests need no clock.
* The form token is BLAKE2b-256 of a fixed label and the secret (`AccountSessionStore::form_token`), so it is bound to
  the session, is not the cookie value, and is not derivable from what the store keeps. Compared in constant time.
* A POST is refused (403) unless `form_post_origin_is_accepted` accepts `Origin` and `Sec-Fetch-Site` (ADR-0784),
  before the body is read. The sign-in form needs nothing else; every other form needs the cookie's live session and
  its form token.
* The sign-in goes through `verify_password_login` with `rate_limit_client_key`, so it shares the throttle of
  `POST /login`. A sign-in always issues a fresh session and ends the one the old cookie named.
* Every page load and every form re-judges the user with `account_sign_in_gate`; a session whose user is locked or
  deactivated ends at once.
* `action` and `device_id` (spec "Account management URL parameters") are read only when they are one of the six
  actions and a valid device ID, and are carried through the sign-in form in hidden fields.
* A device ID the user does not hold, whether unknown or another user's, gets the same 404 page.
* `SameSite=Strict`, unlike the authorisation cookie (`Lax`): nothing reaches these pages from another site with a
  reason to carry the session, so a link from a client opens the sign-in form first.

### Negative Consequences

* A restart signs every browser out of the pages (and nothing else).
* A client's deep link always shows the sign-in form when the user has no live session: one more password entry.
* The device list shows no last-seen time or address; the server keeps none.

## Pros and Cons of the Options

### A database-backed session with a sliding expiry

* Bad, because it is a standing credential that a browser left open keeps alive, and it needs a table, a migration and
  a retention rule for no gain.

### No session

* Bad, because a user who follows a client's link to sign out a device would type the password for every page.

## Links

* Builds on [ADR-0782](0782-pending-authorisations-and-authorization-codes-are-in-memory-hashed-bounded-and-never-evicted.md),
  [ADR-0784](0784-oauth-pages-use-a-same-origin-referrer-policy-and-a-form-post-must-name-this-server-s-origin.md) and
  [ADR-0786](0786-the-query-of-an-oauth-request-is-never-logged.md)
* Differs on purpose from [ADR-0787](0787-every-oauth-authorisation-asks-for-the-password-and-no-browser-session-is-kept.md),
  which keeps no session for the authorisation pages
