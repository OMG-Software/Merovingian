# A remote member may leave through a server whose local members have all left

* Status: accepted (supersedes the "no exception" sentence of point 1 of [ADR-0591](0591-a-refused-send-join-leave-or-knock-is-never-stored-and-needs-local-interest.md))
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement invite-rejection regression after the run-4 audit fix F-12 (1.0.2).

## Context and Problem Statement

ADR-0591 point 1 makes the membership acceptor refuse `send_join`, `send_leave` and `send_knock` for a room in which
no user of this server is joined, invited or knocking. It added no exception for a flow this server started, and it
accepted that a remote invitee could no longer reject an invite once the local inviter had left.

Complement tests exactly that. A local user invites a remote user, then leaves. The invitee's server asks this server
for `make_leave` / `send_leave`, because this server sent the invite and, for a pre-v12 room, the room ID names it. The
answer was 403, and the invitee was left with an invite they could not reject. The spec ("Leaving Rooms (Rejecting
Invites)") lists no refusal for this case.

Can a leave be admitted without reopening F-12, where any server could make this server store membership events for
any room it knows?

## Decision Drivers

* F-12: a stranger must not be able to make this server store, recompute or publish anything.
* F-10: a refused or ended member must learn no room state.
* A remote user who holds a `join`, `invite` or `knock` row here must be able to end it.

## Considered Options

* Admit a `send_leave` whose sender, a user of another server, holds a `join`, `invite` or `knock` row in the room.
  All other gates still run.
* Keep ADR-0591 as written and record the test as an expected failure.
* Admit every `send_leave` for a known room.

## Decision Outcome

Chosen option: the first. `membership_admission_refusal` lets a `send_leave` through when `remote_member_may_leave`
holds for the envelope's sender. The agreement gate (an `m.room.member` leave about its own sender, from a user of
the origin) and the outcome gate (auth must accept it against current state) still run, in that order, before
anything is stored. The leave turns the row into `leave`, so a second leave is refused: each row admits one stored
event, not one per request. `send_leave` carries no state, so F-10 is not affected. `send_join` and `send_knock` keep
the gate unchanged.

### Positive Consequences

* A remote invitee can reject an invite after the local inviter has left. A remote member can leave a room whose local
  members are gone.

### Negative Consequences

* A server whose user holds such a row can make this server store one leave, which this server then sends to the other
  servers in the room. The row exists only because this server accepted that user earlier.

## Pros and Cons of the Options

### Keep ADR-0591 as written

* Good, because the gate stays a single rule.
* Bad, because an invite this server sent could never be rejected, and the spec gives no reason to refuse.

### Admit every `send_leave` for a known room

* Bad, because it reopens F-12 for any user of any server.

## Links

* Supersedes part of [ADR-0591](0591-a-refused-send-join-leave-or-knock-is-never-stored-and-needs-local-interest.md)
