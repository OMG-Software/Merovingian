# Held room state is current only while a user of this server is joined

* Status: accepted
* Date: 2026-10-30

## Context and Problem Statement

A federated leave (`make_leave` / `send_leave`) leaves this server with a membership row and no leave event,
so the room state it holds still says the user is joined. Since ADR-0293 a refusal from the invitee's server
is final: the inviter's `PUT /v2/invite` was judged against that stale state ("cannot invite already-joined
user") and the user could never be invited again (Complement `TestRestrictedRoomsRemoteJoin`, "Join should
succeed when invited"). The Server-Server API, "Inviting to a room" and "Leaving Rooms", say nothing about
state kept after the last local user left. The restricted-join rule already treats it as not current.

## Considered Options

* Store the signed leave in the room (the leave template's `prev_events` may not be held, and the event would
  need the full bookkeeping a federated leave does not do).
* Judge an invite against held state only while a user of this server is joined to the room.

## Decision Outcome

The second. The invite handler treats a room as held only while a user of this server has a `join` row for
it. Otherwise it stores the invite like one for an unknown room (an outlier with a state row for the
invitee). A target who is banned is still refused, by the membership-row check that does not depend on state.

For a room this server is in, the handler still records the invitee's row and invite metadata but stores no
event: the transaction that carries the same event places it. `/sync` shows such an invite only once the
room's state has it (`invite_awaits_room_state`). Showing it earlier (the order ADR-0293 produces) let the
invitee act on an invite the state lacked, and join, leave and reject were refused with 403 (Complement
`TestFederationRoomsInvite`, "when homeserver is already participating in the room"). Rejected: placing the
event from inside the handler. It would take a room stripe lock under `runtime.mutex`, which the worker relay
path already holds (a lock-order inversion), and the event's `prev_events` may not be held yet. ADR-0285's
`already_stored` answer is unaffected, since the handler stores no event for such a room. Sliding sync does
not apply the gate yet.
