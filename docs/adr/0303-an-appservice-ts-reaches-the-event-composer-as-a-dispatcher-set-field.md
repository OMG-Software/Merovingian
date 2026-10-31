# An appservice's `ts` reaches the event composer as a field the dispatcher sets, never as a query string

* Status: accepted
* Date: 2026-10-30

Technical Story: Complement `TestJumpToDateEndpoint` (events sharing a timestamp, sent by an application service with `?ts=`)

## Context and Problem Statement

Application Service API, "Timestamp massaging": an application service may append `ts` to
`PUT /rooms/{roomId}/send/{eventType}/{txnId}` and `PUT /rooms/{roomId}/state/{eventType}/{stateKey}` to set the
event's `origin_server_ts`, and anything origin_server_ts cannot hold "should be rejected by the server as a bad
request". Both routes are rewritten by the client-server dispatcher into an internal `POST /rooms/{roomId}/send`
call to the local router, which composes the event. How does the `ts` reach the composer without letting an
ordinary user set it?

## Considered Options

* Leave `ts` in the query string of the rewritten request and let the local router read it.
* A validated `std::optional<std::int64_t> origin_server_ts` on `LocalHttpRequest`, set only by the dispatcher.

## Decision Outcome

Chosen option: "a field on `LocalHttpRequest`, set only by the dispatcher", because the internal
`POST /rooms/{roomId}/send` route is also reachable with a caller's own query string, so a query-string `ts` would
let an ordinary user stamp events. The dispatcher clears the field on entry, sets it only when the request carries
the masquerade token minted from a matched `as_token`, and validates it first (a decimal integer within
`[-(2**53)+1, (2**53)-1]`, the range of a Matrix integer; anything else is `400 M_INVALID_PARAM`). A `ts` from
anyone else is not read at all.

### Negative Consequences

* `LocalHttpRequest` gains a field that only one dispatcher code path may write. Nothing in the wire parser fills it.

## Links

* The server-side order is untouched: `depth`, `prev_events` and the stream position are composed as for "now".
