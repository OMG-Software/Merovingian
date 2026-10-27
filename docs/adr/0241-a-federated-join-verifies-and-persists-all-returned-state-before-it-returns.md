# A federated join verifies and persists all returned state before it returns

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: Complement federation tests (triage F1), where every event a resident member sent
after this server joined was refused as "sender is not joined to the room".

## Context and Problem Statement

Since 0.10.11 `join_room` split the `send_join` response's `state` array in two. The room-level
events (create, power levels, join rules, our own membership) were verified and persisted before
the join returned, and the join event's after-state group (ADR-0064) was built from them alone.
Every other member's `m.room.member` event was verified and stored afterwards by a background task,
which wrote the `memberships` rows and current state but never the join event's state group.

The premise was that other members' membership is not needed for the room to work. It is: the
auth rules refuse an event whose sender is not joined in the state before it (rule 10 in v10–v12),
and an inbound PDU's state before is resolved from its `prev_events`, which for the first events
after the join name the join event. Every message, membership or state change a resident member
sent after we joined was therefore refused, whether or not the background task had finished.

The spec gives `state` as "the resolved current room state prior to the join event"
([Joining Rooms](../matrix-v1.19-spec/server-server-api.md#joining-rooms)). A joining server may
ask for a reduced response with `omit_members`, and must then learn the full state some other way;
this server never asks, so the resident always returns every member, and there is nothing a
partial join would need to fetch later.

How should a federated join treat the members in `state`?

## Decision Drivers

* Events from members who were joined before us must be authorised against state that holds them.
* Nothing enters the event graph unverified (`src/federation/AGENTS.md` rule 2).
* The owner chose this option (2026-10-27).

## Considered Options

* Verify and persist all of `state` before the join returns, and build the join's state group from
  all of it.
* Keep the background fill, and have it rewrite the join event's state group when it finishes, while
  holding back inbound PDUs for the room until then.
* Keep the background fill, and judge an inbound PDU's sender membership against current state
  while the room is partial.

## Decision Outcome

Chosen option: verify and persist everything before returning. `split_send_join_state_events` and
the background task are removed; `perform_federated_join` verifies the whole filtered `state`
array, with the mutex released and the same bounded parallelism of key resolution, and `join_room`
persists it, builds the join's after-state group from it and writes every member's `memberships`
row in the same request. The worker is told about the room once, when its state is complete.

The second option rewrites an event's state group after it has been used, which ADR-0064 and
ADR-0228 rule out, and needs a hold queue with its own bounds. The third judges events by state
other than the state before them, which is what the auth rules forbid.

### Positive Consequences

* Events from existing members are authorised against the state they were sent in.
* `/members`, `room_has_member()` and the `LocalRoom.members` cache are complete when the join
  returns; there is no partial-state window.
* One less fire-and-forget task holding a reference to the runtime.

### Negative Consequences

* Joining a large room waits for a signing key from every distinct member server before it
  returns. Key resolution is still parallel and bounded (`join_state_key_parallelism`), and keys are
  cached, but a first join to a room spanning hundreds of servers is slower than before.
* A member event whose signature cannot be checked is dropped, as before; that member is then
  missing from the join's state, and their events are refused until state from a later event
  brings them back.
