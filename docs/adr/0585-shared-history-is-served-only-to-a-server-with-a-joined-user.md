# Shared history is served only to a server with a joined user

* Status: accepted; amends [ADR-0282](0282-redact-never-drop-events-a-requesting-server-could-not-see.md)
* Date: 2026-11-09

Technical Story: security audit run 4, finding F-04 (medium).

## Context and Problem Statement

ADR-0282 applies the client-server history visibility settings to a requesting server, and made `shared` visible to
everyone. The only membership test was the room-level gate, which passes for any origin while the room is currently
`world_readable`. So a room that became `world_readable` gave a server with no user in it everything sent earlier
under `shared`. For a client, `shared` needs the viewer to have joined, and `world_readable` covers only events sent
while it was in force.

Which servers may read an event sent under `shared`?

## Considered Options

* A user of the origin is joined now, or was joined in the state at the event
* A user of the origin joined at any point at or after the event
* Only a user joined now

## Decision Outcome

Chosen option: "joined now, or joined in the state at the event". Both are answered from data already at hand: one
walk of the room's current state rows, once per filter, and the event's own state group, which the filter already
reads.

`world_readable` stays visible to any origin, judged by the state at the event as before. Anything else is redacted,
never dropped (ADR-0282). An origin with a joined user now pays nothing per group, because its groups are not
scanned for membership.

`/state` and `/state_ids` stay unfiltered, as ADR-0282 decided.

### Negative Consequences

* A server whose only user joined after an event and has since left no longer receives that event in full, although
  a client in the same position would. It keeps what was sent while it was joined.

## Pros and Cons of the Options

### A user of the origin joined at any point at or after the event

* Good, because it matches the client rule exactly.
* Bad, because proving it walks the room's membership history for each request from a server that chooses the room
  and the events, under a lock that must stay linear in the request.

### Only a user joined now

* Good, because it is the cheapest.
* Bad, because a server that has left could no longer backfill history it was present for and has already served to
  its users.
