# The OAuth browser binding is one `__Host-` cookie, and the pending identifier is the form token

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5b of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

A pending authorisation (ADR-0782) is held under a random identifier that the page carries in a hidden form field.
Anyone who learns that identifier must not be able to finish the login from another browser, and another site must
not be able to post the forms (login CSRF, a forged consent). The plan asks for a `__Host-` cookie and "a token checked
against the cookie" on each form. How many cookies, which value, and what is the form token?

## Decision Drivers

* Two tabs, or a client that starts a second login before the first ends, must not end each other's login.
* No value that grants anything may be readable by script or sent to another host.
* Every form post needs a check another site cannot pass.

## Considered Options

* One cookie, `__Host-mv-oauth`, whose value is reused while well-formed; the pending identifier is the per-form token;
  every post is also held to `Origin` and `Sec-Fetch-Site`
* One cookie per pending authorisation, named after it
* A separate random form token per page, kept in the entry beside the identifier

## Decision Outcome

Chosen option: one cookie reused, the pending identifier as the form token, and the `Origin` check.

* `GET /_merovingian/oauth2/authorize` sets `__Host-mv-oauth` with `core::host_cookie`: `Secure`, `HttpOnly`, `Path=/`,
  no `Domain`, `SameSite=Lax` (the client opens the page with a top-level navigation from another site, which `Strict`
  would strip), `Max-Age=600`, the lifetime of a pending authorisation. Its value is the browser token the entry is bound
  to (`PendingAuthorisationStore::create`), kept by the store only as a hash.
* A request that already carries a well-formed value (64 lower-case hex digits, what `make_oauth_secret` mints) reuses
  it, so every pending authorisation of one browser shares the one token and a second tab does not replace the first
  tab's cookie. Anything else (absent, repeated, malformed) gets a fresh 32-byte value from `make_oauth_secret`.
* Every `POST` must name both the hidden `pending` field and the cookie, and the store answers a wrong pairing exactly as
  an unknown identifier: a 400 page saying the sign-in expired, never a redirect. The identifier is 256 random bits,
  unknown to another site, so it is the per-form token; a second token would be compared against the same entry and
  add nothing.
* Before anything else a `POST` must pass `oauth::form_post_origin_is_accepted` with its `Origin` and `Sec-Fetch-Site`
  (ADR-0784), else a 403 page. A header sent twice counts as absent.

### Positive Consequences

* A leaked pending identifier (a screenshot, a log a proxy kept) is useless without the browser's cookie, and the
  cookie without the identifier names nothing.
* A cross-site post fails on `Origin` even when the browser sends the `Lax` cookie with a top-level `POST`.

### Negative Consequences

* A browser that strips `Origin` from same-origin posts, or refuses cookies, cannot complete a login.
* All pending authorisations of a browser share one token, so a stolen cookie value plus one identifier is enough; both
  are needed in every case.

## Pros and Cons of the Options

### One cookie per pending authorisation

* Good, because each entry has its own secret.
* Bad, because the cookie count grows with abandoned logins and the name itself must carry the identifier.

### A separate form token

* Bad, because it is a second secret compared against the same entry the identifier already names, and must be kept
  and wiped beside it.

## Links

* Refines the plan's "The authorisation flow", step 2
* Builds on [ADR-0782](0782-pending-authorisations-and-authorization-codes-are-in-memory-hashed-bounded-and-never-evicted.md)
  and [ADR-0784](0784-oauth-pages-use-a-same-origin-referrer-policy-and-a-form-post-must-name-this-server-s-origin.md)
