# Federation media multipart is parsed under the lock, with a linear delimiter scan

* Status: accepted
* Date: 2026-10-21

Technical Story: security audit run-1, `med01.federation-multipart-quadratic-boundary-scan`

## Context and Problem Statement

`parse_federation_media_multipart` splits the `multipart/mixed` body a remote server returns for
`GET /_matrix/federation/v1/media/download` into its JSON metadata part and its media part. The
remote server controls the boundary and the body. The parser looked for the delimiter by trying
every offset with a fresh comparison. With a long boundary of repeated characters and a body full
of near-misses, that is O(body × boundary). The parse runs while `runtime.mutex` is held, so a
hostile server could stall every other request.

## Decision Drivers

* The work done under `runtime.mutex` must not grow faster than linearly with input a remote server
  controls.
* RFC 2046 §5.1.1 limits a boundary to 1 to 70 characters.

## Considered Options

* Keep the parse where it is, refuse a boundary longer than 70 characters, and find delimiters with
  a linear (Knuth-Morris-Pratt) scan
* Move the parse out from under the lock

## Decision Outcome

Chosen option: "keep the parse under the lock, cap the boundary and scan linearly". The parsed
parts are `std::string_view`s into the response body. Parsing inside the lock-released region
would mean returning those views alongside the body out of that region. A moved `std::string` does
not keep its buffer when the string is short enough for the small-string optimisation, so the views
could dangle. Avoiding that means copying the media or reworking the response's lifetime. With a
linear scan and a bounded boundary, the work under the lock is O(body). The response body is
already capped at the media upload limit plus a small envelope allowance
(`max_response_body_bytes`).

A delimiter only counts at the start of a line (at the start of the body, or after `\n`) and when
followed by `--`, CRLF, LF or the end of the body. Boundary text inside the media is ignored.

### Positive Consequences

* A hostile remote server can no longer make the parse quadratic.
* No change to the body's ownership or lifetime.

### Negative Consequences

* Any future change to this parser must keep it linear, because it still runs under the lock.

## Pros and Cons of the Options

### Move the parse out from under the lock

* Good, because no parse cost would be held against other requests.
* Bad, because the returned views would have to outlive a move of the body they point into. The fix
  would need copies or a lifetime rework, for no gain once the scan is linear.

## Links

* Related: [ADR-0121](0121-remote-media-fetches-run-on-their-own-pool.md)
