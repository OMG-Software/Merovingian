# A refused send_join, send_leave or send_knock is never stored, and is asked for only in a room with a local member

* Status: accepted (supersedes the part of [ADR-0372](0372-a-resent-send-join-is-answered-from-current-state.md) that answers a soft-failed join with state)
* Deciders: James Chapman
* Date: 2026-11-09

Technical Story: security audit run 4, F-10 and F-12.

## Context and Problem Statement

The membership acceptor behind `send_join`, `send_leave` and `send_knock` judged the event and then stored it
whatever the outcome (status `rejected` or `soft_failed`), answering `403` only for a rejected one. Three defects
followed:

* A soft-failed join (a banned user citing pre-ban history) was answered `200` with the room's state, and a resent
  join was answered from the store whatever the joiner's membership had become since, so a server whose user had
  left or been banned could read the member list, power levels, name and topic (F-10). A soft-failed knock got
  `knock_room_state` the same way.
* The acceptor had no admission check, so any federation server could make this server store, recompute state for,
  publish to sync and notify the worker about a membership event for any room in `store.rooms`, including a room
  with no local member, at the cost of one row per request (F-12).

The spec's Rejection and Soft failure rules describe events a server takes into its DAG. `send_join` and `send_knock`
list `403` for "does not permit the user to join" and "not permitted to knock". What should the resident do with an
event it would reject or soft-fail?

## Considered Options

* Refuse the request with `403` and never store the event
* Store it as `soft_failed` / `rejected`, answer `403`, and cap the rows kept per origin and room (the audit's suggestion)
* Answer a soft-failed join `200` with state, as ADR-0372 did

## Decision Outcome

Chosen option: refuse and never store.

1. **Admission first.** Before anything is stored, and before any state is read for an answer, the acceptor refuses a
   room in which no user of this server has a `join`, `invite` or `knock` membership (`room_has_current_local_interest`,
   the predicate `/send` uses). `send_knock` is answered `404` (the spec lists 404 for "the room ... is unknown to
   the receiving server"); `send_join` and `send_leave` list no code for this case and get `403 M_FORBIDDEN`. No
   exception was added for a flow this server started: a remote user rejecting an invite after the only local member
   who invited them has left now gets the `403` (the resident could not have answered the `make_leave` for such a
   room usefully either). A remote user's join, leave or knock never concerned a local user's row, so
   `concerns_local_member_with_row` is not part of this gate.
2. **The outcome gate.** An event that auth rejects, or soft-fails against current state, is answered
   `403 M_FORBIDDEN` and is not stored. The answer plan, `state`, `auth_chain` and `knock_room_state` are never built.
   Nothing is persisted, `recompute_current_state` does not run, nothing is published to sync, the worker is not
   notified, no stream ordering is taken and no row accumulates per origin. The decision is made first; only an
   accepted event is written. There is no delete after a write.
3. **A resent event** (already stored) is answered only when its stored status is `accepted` and the room's current
   `m.room.member` state for the sender is that very event; otherwise `403`, with no state. A genuine lost-answer
   retry, where the join is still the joiner's membership, works as ADR-0372 describes. The same test covers a resent
   leave and knock, which used to be judged and stored a second time. A row stored `rejected` by an earlier version is
   still refused `403`. Endpoint agreement (`membership_agreement_refusal`: an `m.room.member` about its own sender,
   whose membership is the one the endpoint names, from a user of the origin) runs before this branch, so a stored
   event sent to another endpoint, such as a leave relayed by a worker as `send_knock`, is `400 M_INVALID_PARAM`,
   never a resend answer.
4. **One gate, both paths.** The acceptor is the callback both the direct path (`handle_send_membership`) and main's
   side of the worker relay (`membership_ingest`) call, so main does not trust the worker's decision: the checks
   live in `membership_admission_refusal`, `membership_agreement_refusal` and `membership_outcome_refusal` in
   `local_http_router.cpp`.

ADR-0372 keeps its decision text. Its answer from current state still holds for a join that is the joiner's current
membership; the part that answered a soft-failed join, with the ban in the state, is superseded by 2 and 3.

### Positive Consequences

* A server whose user is banned or has left is told `403` and learns no room state.
* A stranger's membership requests cost no store, state-recompute, sync or worker work, and leave no row.

### Negative Consequences

* A rejected or soft-failed membership event is not in this server's DAG. A later event that cites it as an
  auth event cannot be resolved here and waits for a fetch of it (or is rejected). Such an event is invalid anyway,
  and the spec allows a server not to keep an event whose request it refuses.
* A remote invitee who rejects an invite from a room this server has no local member in is refused.

## Pros and Cons of the Options

### Store soft-failed and rejected events and cap them per origin and room

* Good, because it follows the Rejection and Soft failure sections literally.
* Bad, because it still does the store, state recompute and notification work for every request up to the cap.
* Bad, because a cap evicts or refuses by count, and the next legitimate rejected event of a busy origin is lost
  instead of the attacker's.

### Answer a soft-failed join with state

* Bad, because the state is the room's member list and settings, given to a server whose user the room does not
  permit.
