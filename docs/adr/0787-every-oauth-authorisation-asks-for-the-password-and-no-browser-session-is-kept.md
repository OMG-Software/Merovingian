# Every OAuth authorisation asks for the password, and no browser session is kept

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5b of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), proposal P6

## Context and Problem Statement

Under the OAuth 2.0 API a client never sees the password: it sends the browser to `GET /_merovingian/oauth2/authorize`,
and this server's pages sign the user in and ask for consent. Most authorisation servers keep a signed-in browser
session, so a second authorisation from the same browser skips the password and only asks for consent (or nothing,
with `prompt=none`). Should this server keep one?

## Decision Drivers

* A cookie that stands for a signed-in account is a credential: stolen, it signs an attacker's client in.
* An "already signed in" path is a second way into the consent page, and the one most likely to be got wrong.
* Clients ask rarely: a login, an account creation, a re-login after a revoked session.

## Considered Options

* No browser session: every authorisation asks for the password (or creates the account)
* A signed-in browser session in a cookie, for a fixed time, that skips the password

## Decision Outcome

Chosen option: no browser session.

* Every authorisation request shows the login or registration form, and only a password verified (or an account
  created) for that one pending authorisation lets its consent page be approved. `PendingAuthorisationStore::record_user`
  records the user on that entry only; nothing records it for the browser.
* The one cookie the endpoint sets, `__Host-mv-oauth`, binds a pending authorisation to its browser for ten minutes
  ([ADR-0788](0788-the-oauth-browser-binding-is-one-host-cookie-and-the-pending-identifier-is-the-form-token.md)). It
  never stands for an account.
* `prompt=none`, which asks for an answer without any page, is refused with `login_required`, as OpenID Connect Core
  1.0 section 3.1.2.6 says a server that would need to show a page answers. `prompt=login`, `consent` and
  `select_account` show the login form, which they always would.

### Positive Consequences

* No standing cookie to steal, and nothing to sign out of in the browser.
* The consent page is reached only through `verify_password_login` or `create_local_account`, so the failed-login
  throttle and the Argon2id budget cover every authorisation.

### Negative Consequences

* A user who signs in from several clients types the password each time.
* A client that relies on `prompt=none` for a silent re-authorisation gets `login_required` and must show the page.

## Pros and Cons of the Options

### A signed-in browser session

* Good, because a second login from the same browser is one click.
* Bad, because the cookie is a bearer credential for the account, and a forged consent post needs only it.
* Bad, because it adds a sign-out for the browser, an expiry and a revocation to get right.

## Links

* Implements plan proposal P6 for the authorisation pages; the account pages (phase 8) keep their own 15-minute session
* Builds on [ADR-0782](0782-pending-authorisations-and-authorization-codes-are-in-memory-hashed-bounded-and-never-evicted.md)
  and [ADR-0783](0783-login-verification-and-account-creation-are-one-function-each-shared-by-the-matrix-routes-and-the-oauth-pages.md)
