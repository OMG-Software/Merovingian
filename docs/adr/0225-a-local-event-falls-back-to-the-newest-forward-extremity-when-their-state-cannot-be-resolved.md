# A local event falls back to the newest forward extremity when their state cannot be resolved

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-25

Technical Story: 0.12.48; `POST /rooms/{roomId}/leave` answered 500 "membership event
persistence failed" for a public room joined over federation

## Context and Problem Statement

A new local event declares the room's forward extremities as its `prev_events`
(ADR-0064), and its state before is the state resolution of their after-states.
`store_local_event` treated a failed resolution as corruption and refused the event, and
it did so silently, after the event had been signed. One room with an extremity whose
state could not be resolved against the others refused every local event: messages,
state changes and the leave alike, with a 500 and no log line above debug.

How such a room arose: a federated join seeded the join event's after-state but never
removed the forward extremities left from an earlier stay, despite the comment saying the
join became the sole extremity. Every local event after a rejoin then had to resolve the
old stay's state against the new one. In a large public room that resolution fails
closed (an auth-chain event this server never stored, or the state-resolution budget).
The join is fixed separately (it now retires every earlier extremity), but rooms already
in that state, and any future fork whose state cannot be resolved, still need a way out.

What should a local event be built on when the state across all forward extremities
cannot be computed?

## Decision Drivers

* A user must be able to leave a room, and to keep talking in it, whatever this
  server's view of an old fork is.
* The state before a local event must never be invented: it is either the resolution
  this server can compute or the recorded after-state of an event it holds.
* One bad fork must not cost a full resolution, under `runtime.mutex`, on every local
  event in that room (a failed resolution took about 750 ms on the reporting server).
* Spec: `prev_events` "should" name every event "for which it has not yet seen a child"
  (server-server-api.md, PDUs). It is a SHOULD, and the PDU format only requires "the
  most recent events in the room that the homeserver was aware of", at most 20
  (rooms/v12.md).

## Considered Options

* Keep refusing the event (fail closed), now with a warning naming the step.
* Fall back to the newest extremity whose state can be read alone, and retire the others.
* Fall back as above but keep the other extremities.
* Find the largest subset of extremities whose states resolve.

## Decision Outcome

Chosen option: "Fall back to the newest extremity whose state can be read alone, and
retire the others", because it is the only option that both lets the event through and
stops the failing resolution from being repeated.

`basis_for_new_event` (`state_bookkeeping.cpp`) chooses the prev_events and resolves
the state before them once, while the event is composed. When that resolution fails it
logs `event.prev_events.fallback` at warning level and builds on the extremity this
server stored last (stream order, not `depth`, which a remote server chooses) whose
after-state reads on its own. Storing the event removes the cited extremity and every
other one (`retired_extremities`) from the room's extremities, so the next local event
cites only this one. When no extremity has a readable state, it logs
`event.prev_events.unresolvable` and the event is refused (500), as before.

### Positive Consequences

* A room with an unresolvable fork accepts local events again, and heals on the first.
* The state before a local event is resolved once, not once before signing and again
  in `store_local_event`.
* Every failure on this path logs a warning naming its step (`event.store.failed`,
  `event.persist.failed`, `room.leave.failed`, `room.join.failed`).

### Negative Consequences

* The retired forks are not merged by this server's next event. Another server that
  still holds them as tips merges them itself; this server's events stop citing them.
* The event's state before is one fork's state, not the resolution of every fork. If the
  retired fork carried state that the resolution would have kept (a ban, a power level
  change), this server's view stops reflecting it until an event descending from it
  arrives. Inbound PDUs are still placed by their own prev_events.
* A remote server that can make the resolution fail (by forking the room against events
  this server cannot fetch) decides which fork this server builds on, by sending the
  newest event. It could already deny every local event in the room; now it can only
  steer which accepted fork is cited.

## Pros and Cons of the Options

### Keep refusing the event

* Good, because the state before an event is always the full resolution.
* Bad, because one unresolvable fork blocks every local event in the room permanently,
  the leave included: the user cannot get out.

### Fall back but keep the other extremities

* Good, because the forks remain tips this server might merge later.
* Bad, because every later local event repeats the failing resolution under the lock,
  and logs the same warning, before falling back again.

### Find the largest resolvable subset

* Good, because it keeps every fork that can be kept.
* Bad, because it needs up to one resolution per extremity (at most 20), each of which
  can take most of a second under `runtime.mutex`.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md):
  a local event's state before is no longer refused outright when the extremities do not
  resolve.
