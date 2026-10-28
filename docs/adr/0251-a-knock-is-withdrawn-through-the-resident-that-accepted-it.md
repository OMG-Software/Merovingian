# A knock is withdrawn through the resident that accepted it

* Status: accepted
* Date: 2026-10-28

Technical Story: review of PR #541 (`POST /leave` on a remote knock)

## Context and Problem Statement

A user retracts a knock by leaving the room (Client-Server API v1.19, "Leaving rooms"), and a
server that is not in the room does that over federation as it rejects an invite: `make_leave`
and `send_leave` to a server in the room (Server-Server API v1.19, "Knocking upon a room").
`leave_room` chose that server from the room ID's domain. A room ID is not routable on its own
(ADR-0242): its domain may have left the room, the knock may have gone through a different
server the client named, and a version 12 room ID names no server at all, so the leave fell to
the local path and was refused with 403 for want of the room's auth events. Which server should
a knock's withdrawal go to?

## Considered Options

* The room ID's domain, as before
* The servers in the knock's stripped state (`knock_room_state`)
* The server that accepted the knock, kept with the knock record

## Decision Outcome

Chosen option: "the server that accepted the knock", because it is known to be in the room and
to accept federation from this server for it, and it is the only one of the three that exists
for every room version. `perform_federated_knock` returns the candidate that answered
`make_knock` and `send_knock`; `knock_room` stores it in the knock's `invites` row
(`resident_server`, empty for an invite and for a knock on a room this server is in); and
`leave_room` sends a knock's `make_leave` and `send_leave` there, falling back to the room ID's
domain only when the record names no server. The `membership` row and the record change only
after `send_leave` succeeds.

### Positive Consequences

* A knock on a version 12 room, or one routed through a `via` server, can be retracted.

### Negative Consequences

* The `invites` table gains a column (`resident_server TEXT NOT NULL DEFAULT ''`), edited into
  the v1 schema in place since 1.0.0 is not cut (ADR-0224).
* If the accepting resident later leaves the room, the withdrawal fails with 502 rather than
  trying another server. The knock can still be overridden by the room (a denial is a leave sent
  by a member).

## Pros and Cons of the Options

### The room ID's domain

* Bad, because a room ID is not routable (appendices, "Room IDs"; ADR-0242), and a version 12
  room ID has no domain.

### The servers in `knock_room_state`

* Good, because no schema change is needed.
* Bad, because stripped state names senders, not servers known to be resident now, and the
  resident chooses which events to include, so it may name no server at all.
