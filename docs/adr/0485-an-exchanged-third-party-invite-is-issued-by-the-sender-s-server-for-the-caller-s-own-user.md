# An exchanged third-party invite is issued by the sender's server, for the caller's own user, and never moves a member

* Status: accepted
* Date: 2026-11-04

Technical Story: November project analysis, SS2

## Context and Problem Statement

`PUT /exchange_third_party_invite/{roomId}` asks "the inviting homeserver" to turn a third-party invite into an
`m.room.member` invite. The body's fields are the caller's: `sender`, `state_key`, `room_id`, `signed`, and an optional
`display_name`. The authorisation rules (rooms/v11.md rule 4.3.1) accept the event when `signed` is signed by a key of the
room's `m.room.third_party_invite` and the sender and `mxid` match, and they skip the usual checks on the target's current
membership. Which of the remaining checks does this server add?

## Decision Drivers

* An event is signed for a user only by that user's server (the sender's domain must have signed it).
* A `signed` object is delivered once but never expires. Anyone who held it could replay it.
* Interoperability: servers in practice send no `display_name`, though the spec table lists it as required.

## Decision Outcome

`exchange_third_party_invite` (`room_service.cpp`):

1. **The sender must be a user of this server**, joined to the room. Otherwise 403: this server cannot sign the invite for
   another server's user. (`onbind` forwards the exchange to the sender's server in that case.)
2. **The caller must be the invited user's own server** (`handle_exchange_third_party_invite`: the X-Matrix origin equals the
   server of `state_key`, else 403). The caller is the server the identity server told about the binding; any other server
   replaying a `signed` object would be inviting someone else's user.
3. **A user already `join`ed or `ban`ned is refused (403), and one already `invite`d is a success that stores nothing.**
   Rule 4.3.1 lets a third-party invite stand in for the membership checks, so without this a replayed object would move
   a joined member to `invite`. The refusal sits in front of the auth rules, which still run on the composed event.
4. **`display_name` is optional on receipt and never read.** The event's `display_name` is the room's own
   `m.room.third_party_invite` one, so a hostile caller cannot put text of its choosing into the room.
5. The signature check is the auth rules' (`compose_signed_event` authorises the event before it is signed and stored):
   the invite for the token must exist, its sender must be `sender`, `signed.mxid` must be the invitee, and a signature in
   `signed` must verify against a key of that invite.

### Negative Consequences

* A user who left, or was kicked, can be invited again by a fresh identity-server object; that is what a new invite is.
* A remote sender's room can only be reached through the sender's own server; if it is down the invite waits for the
  identity server's retry.

## Links

* [ADR-0484](0484-answer-the-third-party-invite-endpoints-in-main-and-bound-the-unauthenticated-one.md)
