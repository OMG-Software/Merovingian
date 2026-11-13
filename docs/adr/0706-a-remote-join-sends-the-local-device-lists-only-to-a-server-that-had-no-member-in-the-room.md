# A remote join sends the local device lists only to a server that had no member in the room, from the roster's per-server group

* Status: accepted
* Date: 2026-11-12

## Context and Problem Statement

Every accepted remote join (send_join, a join PDU, a member state resolution flipped to join) called
`broadcast_local_device_lists_to_remote_joiner` under `runtime.mutex`. It listed the room's local members by checking each
roster entry against every account (`local_user_exists`), then queued one `m.device_list_update` per device of every local
member for the joiner's server, even when that server already shared the room or the event was a profile change. A remote
server with one user in a large room could repeat this at the PDU rate limit (run-3 finding C32).

## Considered Options

* Send only when the joiner's server had no joined member in the room before the event, and find the local members through
  a per-server group kept inside `RoomMembers`
* Keep sending on every join but find the local members faster
* Remember per (room, server) that the lists were sent, in a new table

## Decision Outcome

Chosen option: "Send only when the joiner's server had no joined member in the room before the event, and find the local
members through a per-server group kept inside `RoomMembers`".

The gate is read before `apply_membership_to_roster` changes the roster (`joiner_server_already_in_room`) and passed to the
broadcast, because after it the joiner is in the roster and "before" cannot be told. A server that already has a joined
member has the lists and is told of later changes by the ordinary device-list fan-out. A user who leaves and joins again
while being the server's only member opens the gate again: that is a real transition, and its cost is now the local
members' devices alone.

`RoomMembers` keeps a hash map from server name to the members of that server, maintained by `add`, `remove` and `clear`
beside the list and the set (ADR-0496). The local members of a room are that map's group for this server's name. The
account list is not consulted again: a roster member with this server's name joined through this server.

Why not only a faster lookup: the amplification is the re-send itself, which the gate removes; a faster lookup would leave
every profile change queueing every device of every local member.

Why not a table of "already sent": it would need persistence, expiry and a reload test for a fact the roster already holds.
