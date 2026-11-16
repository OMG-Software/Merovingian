# An OAuth page response is marked in its type and gets no CORS headers

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 5a of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

The client-server boundary (`handle_client_server_request`) adds `Access-Control-Allow-Origin` and `Vary: Origin` to
every complete response, as the spec requires of the Matrix API, and the client API's `wrap()` re-encodes a router
answer as JSON. An OAuth 2.0 page is HTML for a browser at this server's own origin; a CORS header on it would let
another origin read a page holding a pending authorisation identifier, and a rewrite would break its headers. Where is
the exception made?

## Considered Options

* A `page` flag on `LocalHttpResponse`, read at the one boundary that adds the headers and by `wrap()`
* A list of page paths at the boundary
* A header the page sets and the boundary looks for

## Decision Outcome

Chosen option: the flag in the response type.

`LocalHttpResponse::page` is set by whoever builds a page with `oauth::page_headers`. `apply_client_response_headers`
(the boundary's call, public so a test can hand it a built response) adds only `X-Content-Type-Options: nosniff` to a
page, never a CORS header, preflight or not; `wrap()` returns a page unchanged. The flag is internal: never written to
the wire.

### Positive Consequences

* A page cannot gain a CORS header by being served from a new path; nothing has to keep a path list in step.

### Negative Consequences

* A handler that builds a page and forgets the flag gets CORS headers; the page tests of phase 5b check every page.

## Pros and Cons of the Options

### A path list at the boundary

* Bad, because a page served at a path the list misses is readable cross-origin.

### A marker header

* Bad, because a header is written to the wire, and anything that copies headers could forge or drop it.
