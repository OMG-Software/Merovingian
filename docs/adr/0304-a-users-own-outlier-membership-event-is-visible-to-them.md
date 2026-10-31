# A user's own outlier membership event is visible to them

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestFederationRoomsInvite/Parallel/Invited_user_has_'is_direct'_flag_in_prev_content_after_joining`

## Context and Problem Statement

An invite this server receives for a room it holds no state for is stored as an outlier with no state
group, and so is the leave that rejects one (ADR-0294). `sync::HistoryVisibility` judges an event with no
state group only by the user's own membership timeline (rule 2: visible if they were joined when it was
sent), because the state at the event cannot be read. An invite precedes the join, so the invitee was
never "joined" at it, and the invite was judged not visible to the very user it invites.

That hid ClientEvent `unsigned.prev_content` after a federated join: "only returned if ... the client has
permission to see the previous event", and the previous event of the invitee's join is that invite. The
spec does not say how a server judges an event it holds without state.

## Considered Options

* Treat the user's own outlier `m.room.member` event as visible to that user
* Keep judging it by the membership timeline
* Record a state group for the received invite

## Decision Outcome

Chosen option: "Treat the user's own outlier `m.room.member` event as visible to that user", because the
spec already gives the user that event: the invite through `/sync`'s `invite` section ("Joining rooms",
invites) and the rejecting leave through `rooms.leave`. Showing its content again reveals nothing new.
The rule is narrow: status `outlier`, no state group, `type` `m.room.member`, `state_key` the asking
user. Every other event keeps the existing checks, and no other user gains anything.

### Positive Consequences

* A federated join that replaces an invite carries `unsigned.prev_content` (the invite's content,
  `is_direct` included) for the joining user.

### Negative Consequences

* None known. Recording a state group for the invite was rejected: this server holds none of the room's
  state when the invite arrives, so any group would be invented.

## Links

* Related to [ADR-0084](0084-history-visibility-is-judged-on-the-recorded-state-at-each-event.md)
* Related to [ADR-0294](0294-the-leave-that-rejects-a-remote-invite-is-kept-as-an-outlier.md)
