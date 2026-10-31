# Auth chains this server serves include the create event a room version implies

* Status: accepted
* Deciders: project owner
* Date: 2026-10-30

Technical Story: Complement run 12 (`TestEventAuth/returns_auth_events_for_the_requested_event`, `TestEventAuth/returns_the_auth_chain_for_the_requested_event`)

## Context and Problem Statement

From room version 12 the `m.room.create` event is never listed in an event's `auth_events`: the room ID is its
reference hash, which implies it. `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` returned the closure
of the event's `auth_events`, so for a v12 room its answer never held the create event, one event short of what a
peer (Complement's gomatrixserverlib) counts as the chain. Does the auth chain a v12 server serves include the
create event?

The spec passages disagree on a literal reading. rooms/v12.md "Auth rules": "The `m.room.create` event MUST NOT be
selected for `auth_events` on events. The `room_id` (being the `m.room.create` event's ID) implies this instead."
rooms/v12.md "Auth chain": "the set containing all of *E*'s auth events, all of *their* auth events, and so on
recursively ... the events reachable by walking the graph induced by an event's `auth_events` links." The first
says the room ID implies the create event as an auth event; the second defines the chain by `auth_events` links.
The Server-Server API only says `event_auth` "Retrieves the complete auth chain".

## Decision Drivers

* A receiving server needs the create event to apply the auth rules (the `m.federate` check, the creators).
* The wording of the two v12 passages does not settle the question; the owner decided.
* The change must not alter what this server accepts, nor state resolution.

## Considered Options

* Serve the chain as the literal `auth_events` closure (create event absent in v12).
* Include the implied create event in every auth chain this server serves.
* Also change the auth chain used by state resolution's auth difference.

## Decision Outcome

Chosen option: "include the implied create event in served auth chains", because a peer needs it and the
room ID makes it an implied auth event of every event.

* Applies to a room whose version has `create_event_is_room_id` (v12 and up), and only when this server holds the
  room's create event (`implied_create_event_id`, `event_query.cpp`, found through the room's current `m.room.create`
  state row). Earlier versions list the create event in `auth_events` and are unchanged.
* Applies to the auth chains served by `GET /event_auth/{roomId}/{eventId}` (`build_event_auth_response`),
  `GET /state/{roomId}` (`auth_chain`) and `GET /state_ids/{roomId}` (`auth_chain_ids`, the same set by ID). The
  `send_join` answer's `auth_chain` already holds it, because the resident's walk starts from the pre-join state,
  which contains the create event; a conformance scenario pins that.
* The event is added once (deduplicated), and never to its own chain. It counts toward
  `max_event_auth_chain_events`: a chain that reaches the bound only with it is refused as too large, never cut
  (ADR-0284).
* Not changed: state resolution's internal auth-chain and auth-difference computation, and what this server
  accepts from others.

### Positive Consequences

* A peer receives a chain that authorises every event it contains, including the create event.

### Negative Consequences

* The served chain differs from the literal `auth_events` closure that rooms/v12.md "Auth chain" describes; if
  the spec later says the chain excludes the implied create event, `append_implied_create_event` is the one place
  to remove.
