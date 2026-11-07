# Invite permission is decided where account data is held, and createRoom drops only a remote block

* Status: accepted
* Date: 2026-11-07

## Context and Problem Statement

Client-Server API "Invite permission" (SS7): a local user whose global account data `m.invite_permission_config` has
`default_action: "block"` must be refused every invite with 403 `M_INVITE_BLOCKED`. The invite can arrive over
federation (a federation worker relays it to main), or from a local client through `POST /invite`, `PUT /state`, or
the `invite` list of `POST /createRoom`. For createRoom the spec allows one invite to be rejected "whilst the room
creation as a whole succeeds". Where is the decision made, and what does createRoom do?

## Considered Options

* Decide in the federation worker and in each client handler from a copy of the account data.
* Decide in the handler on main (`invite_handler`, `invite_user`, `send_event_as_user`, createRoom), through
  `invite_permission_blocks`, and carry `M_INVITE_BLOCKED` in `OperationResult::errcode`.
* For createRoom: create the room and drop every blocked invite; or refuse the request when a local invitee blocks.

## Decision Outcome

Chosen: decide on main only. The worker has no account data and relays invites to `invite_handler`
(`invite_ingest`), so the check sits there, before the event is signed or stored; a worker answer cannot skip it.
`invite_permission_blocks` reads the row through `find_account_data_content` (the per-user index), never a scan, and
treats anything but the string `"block"` as "invites as normal".

createRoom, a LOCAL invitee who blocks is found before `create_room` runs and the whole request is 403
`M_INVITE_BLOCKED` with nothing created: the creator learns at once and no room is left behind. A REMOTE invitee's
server answers the offer after the room exists; its 403 `M_INVITE_BLOCKED` drops that one invite (logged
`room.create.invite_blocked`, never queued) and createRoom answers 200. A created room is never deleted or failed.
`POST /invite` for a remote invitee whose server blocks answers the client 403 `M_INVITE_BLOCKED` with nothing stored
and nothing queued; `deliver_remote_invite` reports the errcode (`RemoteInviteResult::errcode`) from the fixed value
`OutboundCallResult::remote_errcode`, never from the remote's text.

### Negative Consequences

* `PUT /state/m.room.member` with membership invite for a REMOTE invitee still stores the event and queues it (it is
  not offered to the invitee's server first); only a local invitee's block is enforced there.
* The invite event a createRoom stored for a remote invitee that blocked stays in the room's state; only the offer is
  dropped.
