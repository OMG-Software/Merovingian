# createRoom's invite_3pid is judged before the room exists and never undoes it

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`POST /createRoom` took `invite_3pid` and ignored it: a 200 and a room, with no third-party invite sent. The spec lists
the events the parameter implies (`m.room.third_party_invite`) and says nothing of a malformed entry, an identity server
this server does not trust, or one that fails. Each entry is a blocking identity-server round trip on a request thread.

## Decision Outcome

- An entry that is malformed (400 `M_BAD_JSON`, or `M_INVALID_PARAM` for a bad `id_access_token`) or names an identity
  server outside `trusted_servers` (400 `M_SERVER_NOT_TRUSTED`) refuses the whole request before the room exists, so a
  client never gets a room that silently lacks the invite it asked for.
- The entries share `max_create_room_invites` with `invite`: the cap counts both lists (ADR-0316).
- The entries are sent with `invite_user_by_threepid` after the room and the remote `invite` offers, under the same
  ADR-0079 slot and the same `OutboundDeadline` as those offers. Each call is given at most what is left of the
  deadline (`max_total_seconds`); an entry the slot or the time does not cover is skipped.
- An identity server that fails, or is not reachable, once the room exists does not undo the room: it is logged as
  `room.create.invite_3pid_failed` and createRoom answers 200, as it does for a remote invitee that cannot be reached
  (ADR-0307).

Rejected: failing createRoom when an identity server call fails. The room and its other invites already exist and are
visible to the invitees, so a 4xx/5xx would lead the client to retry and create a second room; deleting a room is not
possible. Rejected: giving each entry the identity-server client's own timeouts (up to 30 s each, 100 entries).
