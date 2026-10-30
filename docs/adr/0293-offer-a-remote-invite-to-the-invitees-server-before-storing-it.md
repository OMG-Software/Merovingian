# A remote invite is offered to the invitee's server before it is stored or sent on

* Status: accepted
* Date: 2026-10-30

## Context and Problem Statement

`POST /rooms/{roomId}/invite` and the `invite` list of `createRoom` stored the invite, sent it to the
room's other servers, answered the client, and only then queued `PUT /_matrix/federation/v2/invite` for the
invitee's server. The invitee's server could therefore learn of the invite after a third server, and after
the invitee had acted on what the third server showed (Complement `TestFederationRejectInvite`, and
`TestFederationRoomsInvite` "is_direct", where the invitee joins as soon as `createRoom` answers). The
Server-Server API, "Inviting to a room", says a request to the invitee's server "to have the event signed
and verified must be made" and that "once the event has been signed by both ... it can be sent to all of
the servers in the room".

## Considered Options

* Keep the queued invite and let clients race it.
* Make the request synchronously; fail the client request if it cannot be made.
* Make the request synchronously; fall back to the queue when the invitee's server gives no usable answer.

## Decision Outcome

Chosen option: the third. `invite_user` composes and signs the event, calls `deliver_remote_invite`
(`runtime.mutex` released for the round trip) and only then stores it and sends it to the room's other
servers. `createRoom` calls the same function after the room exists, when no other server is in it yet. An
answer of 4xx other than 408/429 is final and fails the `/invite` request (403 stays 403, others become
502; `createRoom` logs it). No answer, 408, 429 or 5xx queues the invite as before
(`queue_remote_invite`), because an unreachable peer must not make invites impossible and a retry is what
the queue is for. That fallback is the one case where the room's servers hear of the invite first.

### Consequences

* A server that is down makes `/invite` wait for `remote_timeout_seconds` before falling back. The call
  holds a request thread, as a federated leave does.
* The event is composed before the lock is released and stored after it is re-taken, so a concurrent event
  may have been stored in between; the invite is then a fork, which the DAG allows. The inviter's presence
  in the room is checked again.
* The invitee's signature in the response is not yet merged into the stored event.
