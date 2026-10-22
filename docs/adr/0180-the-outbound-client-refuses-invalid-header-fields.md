# The outbound client refuses header fields that are not valid HTTP

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `sp02.is-token-crlf-header-injection`

## Context and Problem Statement

`id_access_token` from client JSON became an `Authorization: Bearer` header on requests to an
identity server. Nothing between the JSON parser and the wire checked it, and the pinned libcurl
writes header lines verbatim, so a token containing CR/LF added header lines to the request.

## Decision Drivers

* Many callers build outbound headers, and some values come from clients.
* The check must happen before any DNS, connection or header serialisation.

## Considered Options

* Validate every header in the outbound client (`validate_outbound_request` and `perform`)
* Validate `id_access_token` where each client route reads it

## Decision Outcome

Chosen option: "validate every header in the outbound client". A header name must be an RFC 9110
token and a value must hold no control character other than HTAB. Anything else fails with
`OutboundError::invalid_header` before any network I/O. The push circuit breaker does not count it
as a transport failure.

### Positive Consequences

* One rule at the one boundary every outbound request crosses, covering future callers.

### Negative Consequences

* A client that sends a malformed token gets its identity-server call's failure, not a `400` naming
  the field.

## Pros and Cons of the Options

### Validate at each client route

* Bad, because there are five routes that read the token, and a sixth would be easy to miss.

## Links

* Related: `src/http/AGENTS.md`
