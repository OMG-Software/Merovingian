# A response head the formatter cannot write safely is refused with a 500

* Status: accepted
* Date: 2026-11-15

Technical Story: phase 1 of the OAuth 2.0 API plan (`docs/todos/oauth-2-0-api.md`)

## Context and Problem Statement

`format_response_head` in `homeserver/HttpServer.cpp` replaced the default `Content-Type` only when a handler spelled
the header exactly `Content-Type`, so `content-type` produced two. It skipped a header whose name or value was invalid
without a word, so a `Location` or `Content-Security-Policy` holding a CR would vanish from the response. It wrote a
handler's `Content-Length` or `Connection` beside its own, and a federation worker, the process most exposed to hostile
traffic, chooses the headers of every answer it relays. The OAuth 2.0 pages will set `Content-Type`,
`Content-Security-Policy`, `Set-Cookie` and `Location` on 200, 302 and 303 responses. What should the formatter do with
a header it cannot write safely?

## Decision Drivers

* A response must never carry two `Content-Type` headers, or two framings.
* Dropping a header silently can remove a security control (a content security policy, a cookie deletion).
* Header names are case-insensitive (RFC 9110 section 5.1).

## Considered Options

* Keep dropping invalid headers, and only fold the `Content-Type` match.
* Repair: strip CR and LF from values, keep the last `Content-Type`.
* Refuse: answer a fixed 500 and close the connection.

## Decision Outcome

Chosen option: "refuse". `http::format_response_head` (moved to `http/ResponseHead.hpp` so it can be tested) matches
names case-insensitively and returns an error, written by `HttpServer.cpp` as a logged `response.head_refused`, a fixed
`500 M_UNKNOWN` with no handler header and `Connection: close`, when the status is outside 200-599, a name is not a
token, a value holds a control character other than HTAB, a handler sets `Content-Length`, `Transfer-Encoding`,
`Connection` or `Keep-Alive`, or `Content-Type` or `X-Content-Type-Options` comes twice (the latter also when it is not
`nosniff`). An empty `Content-Type` still means the default. An unlisted status is written with an empty reason phrase
instead of `OK`.

### Positive Consequences

* A handler bug shows as a 500 and a log line, never as a response missing its policy or carrying a second framing.
* A compromised worker cannot split a response to a remote server with its own `Content-Length`.

### Negative Consequences

* A route that today relies on an invalid header being dropped now fails. None does: no handler sets a framing header,
  and every runtime header goes through `append_header_if_missing`, which validates first.

## Pros and Cons of the Options

### Drop invalid headers

* Good, because a response still goes out.
* Bad, because what goes out lacks the header the handler meant to send, and nobody is told.

### Repair

* Good, because a response still goes out.
* Bad, because a repaired `Location` sends the browser somewhere the handler did not choose.

## Links

* Refines [ADR-0180](0180-the-outbound-client-refuses-invalid-header-fields.md)
