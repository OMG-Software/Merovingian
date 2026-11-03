# A /state or /state_ids answer whose auth chain is over the bound is refused

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: Security audit run 2, F-26 (the auth chain of `/state` and `/state_ids` was collected without a limit)

## Context and Problem Statement

`GET /state/{roomId}` and `GET /state_ids/{roomId}` return the room's state and "the full set of authorisation
events that make up the state of the room, and their authorisation events, recursively" (Server-Server API v1.19).
`build_state_response` and `build_state_ids_response` collected that closure with `collect_auth_chain` at its
default limit of `size_t` maximum, while `/event_auth` already stopped at `max_event_auth_chain_events` and refused
a longer chain (ADR-0284). One request on a room with a long auth history therefore read, and for `/state` parsed
and serialised, an unbounded part of the store. ADR-0284 requires every read on input a remote server controls to
be bounded.

The two answers differ from `/event_auth` in size: the auth chain of a whole state is the closure over every state
event, so it grows with the number of members, not only with the history of one event. A bound of 10000 would refuse
rooms of a few thousand members.

## Considered Options

* Refuse the answer with `RoomReadStatus::too_large` (502 `M_TOO_LARGE`) when the chain is over a bound of
  `max_state_auth_chain_events` (65536), and send none of it.
* Cut the chain at the bound and answer 200.
* Reuse `max_event_auth_chain_events` (10000).
* Leave the chain unbounded.

## Decision Outcome

Chosen option: refuse over 65536. The walk collects one event past the bound, which is how a longer chain is told
apart from one that is exactly the bound; the implied create event of room version 12 and up (ADR-0286) counts
toward it. The status is the one `/event_auth` uses (ADR-0284), for the same reason: the spec defines only a 200
for these endpoints and gives its media download 502 `M_TOO_LARGE` for content "too large for the server to
serve". The number is the default of `security.federation.backfill.max_auth_chain_ids`, the bound this server's own
`/state_ids` consumer applies to an answer it fetches, so this server never serves a chain that it would itself
refuse to read.

A cut chain was rejected for the reason ADR-0284 gives: the receiver cannot tell it is incomplete and fails later.
10000 was rejected because it would refuse ordinary large rooms. Leaving it unbounded was rejected because it is the
defect.

The walk uses the store's event hash index and a visited set, so it costs the events of the chain once each.

### Negative Consequences

* A room whose state's auth closure exceeds 65536 events cannot be fetched over `/state` or `/state_ids` from this
  server, and a joining server must get the state another way. `/event_auth` refuses a chain over 10000, and its
  refusal text points callers to `/state_ids`; a caller refused by both has no whole-chain route here.

## Links

* Refines [ADR-0284](0284-an-auth-chain-longer-than-the-bound-is-refused.md)
* [ADR-0363](0363-state-at-an-event-is-read-from-the-recorded-state-groups.md)
