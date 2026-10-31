# A remote server's signature is merged into this server's own event, only after it is verified

* Status: accepted
* Date: 2026-10-30

Technical Story: PR #546 review findings on ADR-0287 and ADR-0293

## Context and Problem Statement

Two exchanges give this server back an event that another server has signed: the invite handshake
(`PUT /_matrix/federation/v2/invite`, ADR-0293) and the restricted-join fallback (`send_join` to another
resident, ADR-0287). Both first took the other server's copy at its word. The invite code accepted any
object under `event` (an empty one passed) and stored and sent on its own event unsigned by the invitee's
server. The join code verified the resident's copy of the join and stored that copy. A reference-hash event
ID and the signatures are over the redacted form of an event, so a peer can change a field redaction drops
(a display name, `unsigned`) and keep both. Ingestion then finds the content hash wrong and redacts the
event, which also drops fields this server composed.

The spec says the invited server's answer is "The event with the invited server's signature added. All
other fields of the events should remain untouched", and that "once the event has been signed by both the
inviting homeserver and the invited homeserver, it can be sent to all of the servers in the room".

## Considered Options

* Store the other server's copy once its ID and signatures verify.
* Store this server's own event with only the other server's verified signatures added to it.
* Ignore the other server's signature and keep the event as composed.

## Decision Outcome

Chosen option: the second. `with_server_signatures` (`room_service.cpp`) takes this server's signed event
and adds the named signatures of one server, changing nothing else. It is the only way a peer's signature
reaches an event this server composed.

* Invite (`check_invite_answer`, called by `deliver_remote_invite` with `runtime.mutex` released): the
  answer's `event` must have the reference-hash ID of the event sent, and a signature by the invited user's
  server that verifies through `verify_server_signatures_on_event` with keys from `resolve_join_state_key`
  (the same admitted key path the send_join state uses). Only signatures under keys that resolved are
  merged. An answer that fails any check is a refusal (`RemoteInviteOutcome::refused`, 502), not a
  delivery, and is not queued: the same invite would be answered the same way. `invite_user` stores and
  sends the co-signed event; createRoom, which stores its invites first, replaces the stored copy
  (`store_cosigned_invite`).
* Restricted join (`verify_resident_signed_join`): the resident's copy must still have the ID of the join
  this server signed. Its authorising-server signatures are merged into this server's own join, the
  combined event is verified (`filter_verified_send_join_events`), and that is what `pdu_sink` receives.
  A resident that changed the display name therefore changes nothing that is stored.
* A `pdu_sink` answer of `already_stored` for that join is a success only if the stored event is that join,
  is accepted, is the user's current `m.room.member` state and the user's membership is `join`
  (`join_event_made_member`). A copy stored as an outlier, soft-failed or rejected did not make the user a
  member, and the join is reported as failed.

### Consequences

* A failed key lookup for the invited server refuses the invite (502), though the server answered. The
  answer arrives over a TLS connection to that server, so its key endpoint is normally reachable; a
  transient miss costs the client one retry.
* The stored `event_signatures` rows of a createRoom invite are not updated by `store_cosigned_invite`; the
  event JSON, which is what is served and sent on, is.
* The invite's signature entry is merged per key ID that resolved, so an unknown or expired key's entry in
  the answer is dropped, as a receiver would skip it.

## Links

* Refines [ADR-0287](0287-a-resident-with-no-local-authoriser-joins-its-user-through-another-resident.md)
  and [ADR-0293](0293-offer-a-remote-invite-to-the-invitees-server-before-storing-it.md)
