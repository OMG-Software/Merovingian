# A profile change succeeds once stored, and reaches only rooms whose state holds the user joined

* Status: accepted
* Date: 2026-10-22

Technical Story: Element reported `500` on `PUT /profile/{userId}/displayname` although the new
display name was saved and `GET /profile` returned it.

## Context and Problem Statement

`PUT /_matrix/client/v3/profile/{userId}/{keyName}` stores the field and then, per "Events on
Change of Profile Information", sends an `m.room.member` join carrying the profile to every room the
user is a member of, and an `m.presence` update. 0.12.30 (PR #513 review) answered `500` whenever
one room or the presence write failed, so that the client would retry. Two problems followed:

* The field was already set. The spec's responses for the endpoint are `200` "The profile field was
  set.", `400`, `403` and `429`; a `500` told the client a change that had happened had failed.
* A room that refuses the event every time (an unsupported room version, a create event whose row
  is missing, a `m.federate: false` room created on another server) made every later profile change
  fail too. Retrying could never succeed.

Rooms were chosen from the runtime member list (`LocalRoom.members`). That list is kept beside the
room's state and can disagree with it: a state-resolution flip, or the fast-join background fill
re-adding a member who left after the snapshot. Where it names a user whose state is `leave`, the
join sent was authorised as a fresh join, so in a public room a profile change rejoined the user.

## Considered Options

* Answer `200` once the field is stored; log rooms that fail; choose rooms by current state
* Keep `500` on incomplete propagation and have clients retry
* Store the field and propagate in one all-or-nothing step

## Decision Outcome

Chosen option: "answer `200` once the field is stored". `propagate_profile_change` fails only for an
unauthenticated token. A room that refuses the event is logged at warning
(`profile.propagation.room_failed`), and an incomplete run logs `profile.propagation.completed` at
warning with its `failed` count. A room is sent the event only when the runtime member list names
the user **and** the room's current `m.room.member` state for them is a join; a room where only the
list names them is skipped (`profile.propagation.not_member`). The next profile change sends to
every joined room whose membership does not yet carry the profile, so a room that recovers catches
up then.

### Positive Consequences

* The client is told the truth about the field, and one bad room no longer blocks every profile
  change.
* A profile change can no longer rejoin a user to a room they left.

### Negative Consequences

* A room that fails stays on the old profile until the next profile change; nothing retries it in
  between, and the client is not told. Operators see it in the warning log.

## Pros and Cons of the Options

### Keep `500` and have clients retry

* Good, because the client learns that propagation was incomplete.
* Bad, because it reports a stored field as not set, which the endpoint's responses do not allow.
* Bad, because a room that always refuses turns every later profile change into a `500`.

### All-or-nothing

* Bad, because one room this server cannot write to would make the profile unchangeable.
* Bad, because events already sent to other rooms cannot be withdrawn.

## Links

* Refines the 0.12.30 propagation behaviour (CHANGELOG 0.12.30, PR #513)
