# A join tries only the servers the client names

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement `TestRestrictedRoomsRemoteJoinFailOver`, where a join the client routed
through one server succeeded through another.

## Context and Problem Statement

`POST /join/{roomIdOrAlias}` takes `via`, "the servers to attempt to join the room through. One of
the servers must be participating in the room." A room ID in versions before 12 carries a domain,
but the spec says room IDs "are not routable on their own as there is no reliable domain to send
requests to" ([appendices, Room IDs](../matrix-v1.19-spec/appendices.md#room-ids)). This server
appended the room ID's domain to every via list and raced `make_join` against all of them, so a
join through a server that could not authorise it still succeeded through the room's creator.

The spec does not say whether the domain may be an extra candidate.

## Decision Drivers

* The client chooses the route; the server should not override it.
* A join by a bare pre-version-12 room ID with no `via` should keep working.
* The owner decided (2026-10-27).

## Considered Options

* Only the via servers when the client names any; the room ID's domain when it names none.
* Never the room ID's domain.
* Always append the domain (as before).

## Decision Outcome

Chosen option: only the via servers when the client names any usable one (any server but this
one); otherwise the room ID's domain, when it has one. `join_candidate_servers` implements it,
and `POST /knock` uses the same function.

### Positive Consequences

* A join goes where the client sent it; a resident that refuses is the answer.
* A version 12 room, whose ID has no domain, is routed exactly as before.

### Negative Consequences

* A client that names a via server which has left the room no longer reaches the room's creator
  behind its back; it must name a server that is in the room, as the spec requires.
