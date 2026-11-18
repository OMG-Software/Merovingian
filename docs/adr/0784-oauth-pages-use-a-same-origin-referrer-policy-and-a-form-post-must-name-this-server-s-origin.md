# OAuth pages use a same-origin referrer policy, and a form post must name this server's origin

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5a of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

The OAuth 2.0 pages post forms (sign in, create an account, consent) back to this server. A cross-site form post
(login CSRF, consent forged from another site) must be refused. `SameSite` cookies are one line of defence; the request
headers a browser sets, `Origin` and `Sec-Fetch-Site`, are the other. ADR-0772 set `Referrer-Policy: no-referrer`, and
under it some browsers send `Origin: null` on a same-origin form post, which makes the origin check useless. What
policy, and what exact rule?

## Decision Drivers

* No other origin may learn a page's address, whose query carries a state and a pending authorisation identifier.
* A same-origin form post must carry a usable `Origin`.
* The rule must be exact: no prefix match, no case folding, no guessing at ports.

## Considered Options

* `same-origin`, and a form post accepted only when `Origin` equals this server's origin and `Sec-Fetch-Site`, when
  present, is `same-origin`
* Keep `no-referrer` and accept `Origin: null`
* Keep `no-referrer` and rely on `SameSite` cookies alone

## Decision Outcome

Chosen option: `same-origin` with the exact `Origin` rule.

* `oauth::page_headers` sends `Referrer-Policy: same-origin`, and every page's `<meta name="referrer">` says the same,
  so the two never disagree. A navigation to another origin, the client's redirect URI included, carries no Referer.
* `oauth::form_post_origin_is_accepted(base_url, origin, sec_fetch_site)` is the check. The expected origin is
  `form_post_origin(base_url)`: `https://`, the base URL's host in lower case, and `:<port>` only for a port other than
  443 (RFC 6454 section 6.1 leaves the default port out, as browsers serialise it). `Origin` must be present and equal
  it byte for byte: absent, `null`, an explicit `:443`, a trailing slash, another case, scheme, host or port are refused.
  `Sec-Fetch-Site`, when present, must be exactly `same-origin`; absent is accepted, since not every browser sends it.

### Positive Consequences

* A forged cross-site post is refused whatever the cookies say.
* A same-origin Referer is available to this server, and to no one else.

### Negative Consequences

* A browser or privacy extension that strips `Origin` from same-origin posts cannot use the pages.

## Links

* Amends the `Referrer-Policy` of [ADR-0772](0772-page-text-is-escaped-by-type-and-the-page-policy-names-only-a-validated-redirect-origin.md)
