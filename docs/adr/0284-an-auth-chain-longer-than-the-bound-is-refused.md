# An auth chain longer than the bound is refused, never truncated

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-29

Technical Story: PR #545 review (CodeRabbit)

## Context and Problem Statement

`GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` "Retrieves the complete auth chain for a
given event" (Server-Server API v1.19); the spec defines only a 200 response. This server bounds the
walk at `max_event_auth_chain_events` (10000), so one request cannot read an unbounded part of the
store, as every read on input a remote server controls must be bounded.

A chain longer than the bound was answered 200 with its first 10000 events. The receiver could not
tell the answer was incomplete, and failed later, when an event named an auth event it did not get.

## Considered Options

* Refuse a chain longer than the bound with an error, and send none of it.
* Keep answering 200 with the chain cut at the bound.
* Drop the bound and always walk the whole chain.

## Decision Outcome

Chosen option: refuse. `build_event_auth_response` walks one event past the bound; if the chain is
longer, it returns `RoomReadStatus::too_large` with no body, and the handler answers 502
`M_TOO_LARGE`. The status follows the spec's media download, which answers content "too large for
the server to serve" with 502 `M_TOO_LARGE`; `/event_auth` has no error status of its own.

A cut 200 was rejected because it breaks the spec's promise silently: an error tells the receiver to
get the history another way (`/state_ids` and `/event`), a partial chain does not. Dropping the bound
was rejected because a room's auth chain grows with its membership history, and the walk reads every
event in it into one response.

### Negative Consequences

* A server asking for the auth chain of an event in a room with more than 10000 auth events gets no
  chain at all from this server, where it used to get part of one.
