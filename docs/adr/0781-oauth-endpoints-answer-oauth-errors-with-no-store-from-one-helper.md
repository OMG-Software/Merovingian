# OAuth endpoints answer OAuth errors with no-store, from one helper

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 4 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

The OAuth endpoints under `/_merovingian/oauth2/` speak OAuth (RFC 6749 section 5.2, RFC 7591 section 3.2.2), whose
error body is `{"error", "error_description"}`, not the Matrix `{"errcode", "error"}`. The dispatcher's gates in front of
the handlers answer Matrix errors. Which shape does each answer take, and where is it built?

## Decision Drivers

* An OAuth client reads `error`; a Matrix error body means nothing to it.
* Token and registration answers must not be cached (`Cache-Control: no-store`).
* Phases 6 and 7 add more endpoints; their errors must not each be built by hand.

## Considered Options

* One helper, `oauth_error_response` (`OAuthJsonResponse.cpp`), builds every OAuth error from an `OAuthRefusal`, with
  `application/json` and `no-store`; `oauth_json_response` builds every OAuth success the same way. The general body
  cap answers the registration path with `400 invalid_client_metadata`. The gates that judge the request before its
  route (the not-started 503, the 429 rate limit, the 405 and the 404 with OAuth off) stay Matrix-shaped.
* Matrix errors everywhere.
* Each handler builds its own JSON.

## Decision Outcome

Chosen option: the one helper. A body over `max_body_bytes` on the registration path is metadata the server will not
accept, which RFC 7591 names `invalid_client_metadata`, so it is answered by the handler instead of `413 M_TOO_LARGE`.
The 429 is the same for every route and its `Retry-After` is what a client acts on, so it stays shared.

### Positive Consequences

* One place sets the content type and `no-store` for every OAuth answer.

### Negative Consequences

* A client can see a Matrix-shaped 429, 405 or 404 from an OAuth path. These are transport answers a generic HTTP
  client handles by status.

## Pros and Cons of the Options

### Matrix errors everywhere

* Good, because one error shape.
* Bad, because OAuth clients do not read `errcode`, so refusals look like unknown failures.

### Each handler builds its own JSON

* Bad, because a missed `no-store` or content type would go unnoticed.
