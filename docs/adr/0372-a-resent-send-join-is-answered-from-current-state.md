# A resent send_join is answered from current state

* Status: accepted (the part that answers a soft-failed join, with the ban in the answer, is superseded by [ADR-0591](0591-a-refused-send-join-leave-or-knock-is-never-stored-and-needs-local-interest.md): a resent join is answered only while it is the joiner's current membership)
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: review of the F-23 fix in PR #554. Supersedes the resend bullet of
[ADR-0366](0366-a-send-join-is-refused-before-it-is-stored-when-its-answer-cannot-be-delivered.md).

## Context and Problem Statement

ADR-0366 answers a join this server already stored again, so a server whose first answer was lost can
have it. It took the answer's state from the join's `prev_events`, while the first answer takes it from
current state. The two are different when the room changed between `make_join` and `send_join`: the
`prev_events` date from the template. A ban made in that window was in the first answer and missing
from the second, and a server that only ever saw the second took the banned user to be joined until an
event descended from the ban reached it.

`servers_in_room` had the same defect in another form. It reads the room's roster, which holds the
joiner once the join is stored, so the second answer listed the joiner's own server. The spec defines
it as the servers with joined members "before the join".

The spec defines `state` as "the resolved current room state prior to the join event" and has no separate
answer for a repeated request. What should the second answer hold?

## Considered Options

* Current state, with the joiner's own membership put back where the join itself is the current row
* Current state with the joiner's own membership always taken from the state at `prev_events`
* The state at `prev_events` (ADR-0366)
* Store the first answer and repeat it

## Decision Outcome

Chosen option: current state, with the joiner's own membership put back where the join itself is the
current row (`resent_send_join_state`). The answer is never older than the first. A row for the joiner
that is not the join stays: a ban that soft-failed the join, or a later leave or ban.

`servers_in_room` leaves out the joiner unless the answer's own state has them joined, on both answers.

Reading the state at `prev_events` for the joiner's old membership is a read a remote server can repeat at
will, so it runs under `state_read_resolution_limits` (ADR-0365), and over that budget the answer is
503, with nothing stored.

### Positive Consequences

* A lost answer can no longer cost the joining server a ban or demotion the first answer held.
* The second answer does not depend on how old the `make_join` template was.

### Negative Consequences

* The second answer is not always the same as the first. If the room moved on after the join, it holds
  those later events too, though "prior to the join" does not describe them. Each is an accepted event of
  the room, and the joining server would receive it anyway.
* A later ban of the joiner is in the second answer, so the joining server can find that the answer does not
  authorise its join and refuse it. That is the room's actual state.
* A join with several `prev_events` whose resolution is over the read budget is answered 503 on every
  retry, where the ingestion budget might have answered it.

## Pros and Cons of the Options

### Always take the joiner's membership from the state at `prev_events`

Simpler, and it loses the joiner's own ban: a join soft-failed by a ban made after `make_join` leaves the ban
as the current row, and the state at `prev_events` has no ban.

### The state at `prev_events`

It is the state the join's graph position implies, and the state `/state_ids` gives for the join. It is not the
room's current state, and it can hide a revocation.

### Store the first answer and repeat it

Gives an identical answer. Costs a row per join that holds a whole room's state, or a state group the room
never otherwise records, to serve a rare retry.
