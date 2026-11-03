# A send_join is refused before it is stored when its answer cannot be delivered, and omit_members shrinks it

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-23 (`fed.send-join-acceptor-global-state-scan-and-unbounded-response-under-mutex`)

## Context and Problem Statement

The resident's `membership_acceptor` stored a `send_join` and sent it on to the room's other servers, and only then copied
the room's whole state and its auth closure into the answer. Nothing bounded that answer. One federating server can join
any number of its own users to a public room, each event up to 64 KiB, so the answer grew past the worker channel's frame
cap (about 122 MiB with the defaults). The frame was then dropped at the channel with only a log line, the joining server
got 503 after a hold of up to 130 s, its join was already committed and sent on, and a retry of the same event got a 500
from the duplicate. The spec's `omit_members` query parameter, which lets a calling server accept a reduced answer, was
not implemented. What should the resident do when the answer cannot be delivered, and how does a large room become
joinable?

## Decision Drivers

* A join must not be committed and fanned out when its answer is doomed.
* The refusal must be one the joining server treats as retryable, and it must cost the resident almost nothing.
* An honest server must be able to join a large room (`omit_members`, server-server-api.md PUT /send_join).
* The check must be an upper bound of what the channel really carries, or the drop is only moved.
* Work under `runtime.mutex` stays bounded by the room, and the events are copied out once.

## Considered Options

* Plan the answer from event IDs and sizes before the join is stored; refuse with 503 when it does not fit; copy the
  events only once the join is accepted
* Build the answer first, measure it, and store the join only if it fits
* Store the join, and answer a doomed join with a truncated state
* Fix only the channel (a failure frame) and leave the order of commit and answer alone

## Decision Outcome

Chosen option: "plan from IDs and sizes before the store", because it is the only one that never commits a join it
cannot answer, and it copies nothing for a join that is refused.

* `plan_send_join_answer` (`send_join_answer.cpp`) names the events of the answer by ID and sums their JSON sizes, from the
  room's own state entries (ADR-0344) and one walk of the auth DAG. It runs after the join is judged and before it takes a
  stream ordering. A rejected join is answered 403 and is not planned.
* The projected answer must fit two caps (`send_join_answer_limits`): the HTTP body, at `join_response_max_size` (the size
  an operator accepts a join response at, and the size this server accepts when it is the one joining), and the worker
  channel's frame, `worker_ipc_frame_bytes`. A string in a JSON frame at most doubles (canonical JSON holds no raw control
  byte), so the frame is projected at twice the event bytes plus three per entry plus 512 KiB for the rest. That is a
  deliberate upper bound: a room whose state is above about half the frame cap needs `omit_members`.
* A join that does not fit is refused 503 with the reason `...retry with omit_members=true`, nothing stored and nothing
  sent on. 503 is a server error, which a joining server treats as "try another resident", unlike the 400 that means the
  request was invalid.
* `omit_members=true` (parsed in `handle_send_membership`, carried to main in the `membership_ingest` frame as
  `omit_members`) leaves `m.room.member` events out of `state`, except, when the room has no non-empty `m.room.name` and no
  `m.room.canonical_alias`, those of the heroes: the first five joined members other than the joiner, in the roster's order.
  `members_omitted` is true when a membership event was left out, and then `servers_in_room` lists the servers of the
  joined roster. `auth_chain` also carries the join's own `auth_events` closure, which can name a membership event that
  `state` left out (the joiner's invite), and drops the events `state` returns. Without `omit_members` the answer is as it
  was: every state event is also in `auth_chain`. The spec allows the deduplication only with the parameter.
* A join already stored is answered again: for a `rejected` one 403, otherwise 200 with the state before the join (from its
  `prev_events`, `compute_state_before`), nothing stored and nothing sent on a second time. The event ID is the reference
  hash of its content, so it is the same event.

### Positive Consequences

* A doomed join is refused with nothing to undo, in time proportional to the room's state entries and no copy of its events.
* A large room is joinable by a server that sends `omit_members`.
* A lost answer can be had again by re-sending the join.

### Negative Consequences

* The projection is an upper bound, so a room between half the frame cap and the cap is refused for a server that sends no
  `omit_members` although its answer would just have fitted.
* A reduced answer's heroes come from the in-memory roster in its order, not from a stream-ordering sort over invited and
  joined members (the spec says "should"); a room with fewer than five joined members has fewer heroes.
* A re-sent join is answered from the state before it, which a server whose first answer was lost already trusted; the
  `servers_in_room` of a re-send is read from the roster as it is now.

## Pros and Cons of the Options

### Build the answer first, then store

* Good, because the measure is exact.
* Bad, because a refused join still pays for copying the whole room, which a hostile server can repeat.

### Truncate the state

* Bad, because the spec requires the resolved state; a partial state is a silently wrong room.

### Only fix the channel

* Good, because it ends the wait (ADR-0368).
* Bad, because the join would still be committed and fanned out and the server that sent it would still not get the room.

## Links

* Spec: server-server-api.md, PUT /send_join (`omit_members`, `members_omitted`, `servers_in_room`)
* Related: [ADR-0043](0043-base64-encode-ipc-response-bodies.md) · [ADR-0368](0368-an-ipc-response-that-cannot-be-sent-fails-its-requester-at-once.md) · [ADR-0344](0344-index-current-state-by-room-type-and-key-and-trust-it-only-while-in-step.md)
