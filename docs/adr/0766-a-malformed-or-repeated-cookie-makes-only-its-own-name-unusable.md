# A malformed or repeated cookie makes only its own name unusable

* Status: accepted
* Date: 2026-11-15

Technical Story: phase 1 of the OAuth 2.0 API plan (`docs/todos/oauth-2-0-api.md`)

## Context and Problem Statement

The OAuth 2.0 pages bind a pending authorisation, and the account pages a session, to the browser with `__Host-`
cookies. The `Cookie` header that comes back holds every cookie whose domain matches this host, including cookies a
sibling host under the same parent domain set with `Domain=` (cookie tossing): their names, values and number are
not this server's to choose, and many real sites set values with spaces, commas or quotes. How strict should the
reader be, and what does a repeated name mean?

## Decision Drivers

* No second value may be smuggled past a check of the first.
* A cookie that some other site set must not stop this server's pages from working.
* RFC 6265 section 5.4 sends cookies of the same name with no way for the server to tell which is which.

## Considered Options

* Refuse the whole header on any malformed pair or repeated name.
* Take the first (or last) value of a repeated name, and read malformed pairs leniently.
* Read each pair strictly, and make a malformed or repeated name unusable without refusing the others.

## Decision Outcome

Chosen option: "make a malformed or repeated name unusable", `core::RequestCookies`. `find(name)` answers only when
exactly one pair has that name and that pair is well-formed: the name an RFC 9110 token and the value unquoted
`*cookie-octet`. A quoted value is malformed, since this server never sets one. Empty pairs (`;;`) are skipped. The
header is refused whole only for what no browser sends: a control character other than a tab, more than 32 KiB, or
more than 256 pairs. Values are returned without percent-decoding and wiped when destroyed. The only writer,
`core::host_cookie`, can produce nothing but a `__Host-` cookie with `Secure`, `HttpOnly` and `Path=/`, so no other
host can set a cookie under one of this server's names, and a page that reads its own cookie as absent asks the user to
start again.

### Positive Consequences

* A tossed cookie under one of this server's names makes that name absent (the flow restarts); it can never supply
  the value.
* Other sites' cookies, well-formed or not, do not affect this server.

### Negative Consequences

* A browser that holds two cookies of one name (possible only if one was set by this host without the prefix) cannot
  use the page until one expires. Every cookie this server sets has the prefix, so this does not arise from its own
  cookies.

## Pros and Cons of the Options

### Refuse the whole header

* Good, because it is the simplest rule.
* Bad, because any site under the parent domain could stop sign-in for every visitor by setting one odd cookie.

### First or last value wins

* Good, because it matches several frameworks.
* Bad, because which copy a browser sends first depends on path length and creation time, which an attacker can
  arrange, so the check and the use can disagree.

## Links

* Refines [ADR-0812](0812-the-oauth-2-0-api-is-built-into-the-homeserver.md)
