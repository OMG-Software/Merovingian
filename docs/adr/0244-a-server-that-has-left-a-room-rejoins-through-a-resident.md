# A server that has left a room rejoins through a resident

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement `TestRestrictedRoomsRemoteJoin`, "Join should fail with mangled join
rules", where a join the resident would refuse succeeded on the joining server.

## Context and Problem Statement

`join_room` composed a join itself whenever this server still had a `LocalRoom` for the room. It
keeps one after its last user leaves, so a server that was no longer in the room composed a join
from the state it held when that user left, stored it, and told the user they had joined. The
resident never saw the join: membership events composed here were not sent to other servers at
all, and this server was not in the room to send them anyway.

The Server-Server API says a server that is not in a room joins through one that is, with
`make_join` and `send_join` ([Joining Rooms](../matrix-v1.19-spec/server-server-api.md#joining-rooms)).
What counts as "in the room", and where the join goes when the client names no server, are this
server's to define.

## Decision Drivers

* The resident judges a join against the room's current state; this server's copy stops at its
  last user's leave.
* A user who rejoins a room by ID, naming no server, should still reach it.

## Considered Options

* This server is in a room while a user of this server is joined to it. Otherwise a join goes
  through a resident: the `via` servers (ADR-0242), else the room ID's domain, else the servers of
  users joined in the state this server last held.
* Keep composing the join here whenever the room is known, and only send it to the room's other
  servers.
* As the first option, but with no fallback past the room ID's domain.

## Decision Outcome

Chosen option: the first. `this_server_is_in_room` is the test, and `join_room` drops the stale
`LocalRoom` before taking the federated path. `last_known_resident_servers` supplies the fallback;
it matters for a room created here, whose ID names this server.

One exception (review of #541): a room whose `m.room.create` was sent from this server, when the
client names no server and no other server is known to have been in it at our last view, is
joined here. Nobody holds newer state than this server, and there is nobody to ask; without the
exception such a room answered every rejoin `404`. The exception is never taken for a room
created elsewhere, whose last view here may be stale, nor while any resident is known: keeping
every room with no candidate was rejected for that reason.

The second option sends an event built on state this server no longer holds; a resident would
judge it, but this server would already have told the user they joined. The third leaves a room
created here unreachable by ID once its creator has left, though other servers are still in it.

### Positive Consequences

* A rejoin is decided by a server holding the room's current state.
* The joining user learns the outcome the resident gives, refusal included.

### Negative Consequences

* A server that last saw a room long ago may name residents that have since left; the join then
  fails as it would with a stale `via`.
