# The leave that rejects a remote invite is kept as an outlier

* Status: accepted
* Date: 2026-10-30

## Context and Problem Statement

`leave_room` rejects an invite from another server with `make_leave` and `send_leave`. It then recorded only
a membership row. A user's `/sync` reports a left room from the room's stored events and the user's current
`m.room.member` state event, which for an invite to a room whose state this server does not hold is the
invite itself, so `rooms.leave` carried the invite and no leave (Complement `TestFederationRoomsInvite`,
"reject invite over federation for empty room"). The Client-Server API says `LeftRoom.timeline` is the
timeline "up to the point when the user left".

## Decision Outcome

When the user rejects an invite and this server holds no `m.room.create` for the room, the signed leave this
server authored is stored as an `outlier` with a state row for the user and the membership projection, in
one `store_event_with_state` call. This is the same treatment as the invite it replaces and as
`rescind_invite_from_inviter`: no state group, no forward extremity, since this server is not in the room.
`tests/unit/test_store_event_choke_point.cpp` lists the call site as a reviewed ADR-0064 exception.

A room whose state is held is left alone: its leave would need the full bookkeeping, which this path does not
do. An invite ended locally because the inviter's server no longer has the room (`make_leave` 403/404) has no
leave event to keep; its `/sync` still names the invite.
