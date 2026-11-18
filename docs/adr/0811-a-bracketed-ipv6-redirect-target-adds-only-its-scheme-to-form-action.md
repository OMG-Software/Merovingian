# A bracketed IPv6 redirect target adds only its scheme to form-action

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: review finding 8 on `feature/oauth-20-v110`. Amends
[ADR-0772](0772-page-text-is-escaped-by-type-and-the-page-policy-names-only-a-validated-redirect-origin.md).

## Context and Problem Statement

`page_headers(target)` adds the matched redirect URI's origin to `form-action` (ADR-0772), as `ParsedUri::csp_source()`
writes it. A native client may register a loopback redirect URI on `[::1]` (RFC 8252 section 7.3), but the CSP
host-source grammar (CSP3 section 2.3.1) has no form for an IPv6 literal: `http://[::1]:5000` is not a source, a
browser drops it, and Chromium then blocks the redirect after the consent form, so the sign-in never completes. Which
source names such a target?

## Considered Options

* The scheme alone, `http:`.
* No source: the IPv6 loopback redirect is left blocked.
* The bracketed text anyway.

## Decision Outcome

Chosen option: the scheme alone. `csp_source()` returns `scheme:` for a host that starts with `[`, as it does for a
URI with no authority. A redirect URI with an IPv6 host passes `match_redirect_uri` only as a native loopback URI, so
the source is only ever `http:` after a matched loopback target. The bracketed text was rejected because a browser
ignores it, so it blocks the redirect as surely as no source; leaving it blocked was rejected because RFC 8252 names
`[::1]` as a redirect a native client may use.

At the same time `ParsedUri::read` takes an IPv6 host only in the RFC 3986 `IPv6address` grammar (eight 16-bit pieces,
or fewer with one `::`, the last two possibly a dotted IPv4 address with no leading zero), not any run of hex digits,
`:` and `.`; no zone identifier and no `IPvFuture`.

### Positive Consequences

* A native client on `[::1]` completes its sign-in.

### Negative Consequences

* For that one page, `form-action` allows a form post's redirect to any `http:` origin. The page's only form posts to
  `'self'`, and the redirect target is the matched loopback URI, so nothing on the page uses the wider source.

## Links

* Amends [ADR-0772](0772-page-text-is-escaped-by-type-and-the-page-policy-names-only-a-validated-redirect-origin.md)
