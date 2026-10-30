# An invite for an unreachable server is queued before it is stored

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: PR #546 review

## Context and Problem Statement

An invite to a user of another server is offered to that server first (ADR-0293). When the server cannot be
reached, the invite is stored and handed to the outbound dispatch worker, which retries it. The worker can
refuse a transaction: it is shutting down, its queue is full, or the destination already holds its share of
the queue, which is the likely case for a server that is already unreachable. `POST /invite` stored the
invite and then ignored the refusal, so the client was told an invite was sent that reached nobody.

## Considered Options

* Queue the invite before storing it, and refuse the request with 503 when the queue refuses it
* Store the invite first and report success whatever the queue says
* Store the invite first and remove it again when the queue refuses it

## Decision Outcome

Chosen option: "Queue the invite before storing it", because a stored invite cannot be taken back (it is a
room event, already sent to the room's other servers), while a request that has stored nothing can still be
refused. `POST /invite` answers `503` and stores nothing when the queue refuses the invite. createRoom has
already created the room and stored its invites when it offers them, so it keeps answering and logs a
warning (`room.create.invite_not_queued`) for an invite that was neither delivered nor queued.

createRoom offers its invites one after another on the request's thread, and the client chooses how many.
All of them draw from one `OutboundDeadline` (30 s, lowered to `remote_timeout` when configured); an invite
still to be offered when it runs out is treated as unreachable and queued. The offers are client-triggered
outbound calls, so they hold an ADR-0079 client-outbound slot (authenticated callers count too): one for a
`POST /invite`, one for all of a createRoom's offers. The request waits for it within the same deadline, as
`timestamp_to_event` does (ADR-0306), so one client's parallel invites are offered in turn; when none comes,
the invites take the unreachable path above and are queued.

### Positive Consequences

* The client is never told an invite was sent that no server will receive.

### Negative Consequences

* If storing fails after the invite was queued, the invitee's server may receive an invite this server
  does not hold. Its join is then refused by the room's auth rules, as for any invite the room never held.

## Links

* Refines [ADR-0293](0293-offer-a-remote-invite-to-the-invitees-server-before-storing-it.md)
