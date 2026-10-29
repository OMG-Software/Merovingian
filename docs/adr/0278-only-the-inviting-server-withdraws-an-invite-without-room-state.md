# Only the inviting server withdraws an invite this server holds no room state for

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-29

Technical Story: Complement run 10 (`TestFederationRoomsInvite`)

## Context and Problem Statement

A user of this server invited to another server's room has an invite and nothing else of the room. Two
operations then had no way through. A rescinding leave sent by the inviter could not be judged against
room state this server does not hold, and waited for history the resident will not serve to a
non-member. Rejecting the invite composed a leave locally (403), because a v12 room ID names no server.

## Considered Options

* Wait for backfill before applying a rescinding leave.
* Accept a rescinding leave only from the inviting server, for a pending invite, without room state.
* Reject an invite only through `make_leave`/`send_leave`, failing when the inviter cannot take it.
* Reject through the inviter, and end the invite locally when the inviter answers 403 or 404.

## Decision Outcome

* A rescinding leave is applied, as an outlier, only when: it is a leave sent by someone other than its
  target; the target is a local user whose membership is `invite`; the invite was sent by a user of the
  same server as the leave's sender, which is the origin; and this server holds no create event for the
  room. Its signature has been verified before this point, like every PDU's.
* A reject goes to the inviting server through `make_leave`/`send_leave` (spec: "the resident server may
  be the server which sent the invite"). When that server answers 403 or 404 (it no longer has the room),
  the invite is ended as a local `leave` row and nothing is sent. Any other failure is 502 and the invite
  stays. The local ending is this project's choice, confirmed by the owner on 2026-10-29; the
  spec gives no other route.
