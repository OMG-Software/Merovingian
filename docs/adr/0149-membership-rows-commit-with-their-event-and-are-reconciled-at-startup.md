# Membership rows commit with their event, and are reconciled from current state at startup

* Status: accepted
* Date: 2026-10-15

Technical Story: 29 September 2026 security audit, finding DB-4 (the membership row is written in a
separate transaction from the event and current state). Refines
[ADR-0126](0126-local-membership-is-projected-once-at-the-local-event-choke-point.md).

## Context and Problem Statement

A user's membership is the room's current `m.room.member` event (Matrix v1.19 "m.room.member"). The
`membership` table is a projection of it: hydration builds `LocalRoom.members`, which `/joined_members`
and other gates trust, from the rows. Every path that stored a member event wrote the event and its
`current_state` row in one transaction and the `membership` row and invite metadata in later ones. A crash
or write fault between them left a durable ban with a row still saying `join`; after a restart the banned
user was a member again, and nothing put it right.

Two questions: how is the row written, and what happens to a store that already disagrees?

## Considered Options

* **The row and the invite change are statements in the event's own transaction
  (`MembershipProjection`, passed to `store_event_with_state` / `prepare_store_event_with_state`), and
  hydration reconciles rows from current state with a rule that respects rows newer than their event
  (chosen).**
* One transaction for the whole of `store_local_event`: event, state groups, forward extremities and the
  recomputed current state as well. Rejected for now: the state-group and resolution steps read the
  in-memory mirror between writes, so this needs a deferred-write mode that can roll the mirror back on a
  failed commit. The rows DB-4 names (event, `current_state`, `membership`, invites) are the ones the
  read gates depend on, and they now commit together.
* Reconcile by making every row equal to current state. Rejected: some rows are legitimately ahead of
  current state. A federated leave (`leave_room` on a remote room) records `leave` without storing a
  leave event, and an invite received over `/invite` for a room this server holds records `invite`
  before the event reaches current state through a transaction. Overwriting them would bring back a
  rejected invite or a left room after every restart.
* Drop the `membership` table and derive membership from current state when it is read. Rejected as
  out of scope: `/sync` reads the row's `stream_ordering` to decide what changed since a token.

## Decision Outcome

Chosen option: commit the projection with the event, and reconcile at hydration.

* `database::MembershipProjection` names the user, membership and stream ordering, and optionally the
  invite metadata. The store writes the row with an upsert and, in the same transaction, writes the
  invite (`invite`) or deletes it (`join`, `leave`, `ban`). A projection must name the stored state
  event's own user, or nothing is stored. The SQL is all upserts and keyed deletes, so it does not depend
  on the mirror when the commit runs with the lock released (`ingest_pdu_event`).
* Every path that stores a member event passes one: `persist_composed_event` (all local membership
  changes), the federated `join_room`, inbound `send_join`/`send_leave`/`send_knock`, inbound `/invite`
  and inbound PDUs over `/send`. Changes recorded without an event of their own (the federated leave,
  `/invite` for a room this server holds) use `store_membership_projection`, one transaction.
* `persist_composed_event` now writes the row before state resolution has run. If resolution then leaves
  a different member event current (only possible with more forward extremities than one event may
  cite), `finish_local_membership` rewrites the row to that event's membership. ADR-0126 projected
  nothing in that case.
* `reconcile_memberships_with_current_state` runs in `hydrate_local_database`, before the roster is
  built. For each current `m.room.member` event it rewrites the row when the row is missing, when the
  row says `join` and the event does not (a row never grants more than current state), or when the event
  is newer than the row. A row newer than its event is kept. Corrected rows take a fresh stream ordering,
  so incremental `/sync` reports the change. The in-memory rows are corrected even if the write fails
  (the federation worker's store is read-only): they then match current state, which is already durable.

### Positive Consequences

* A ban, kick or leave is never durable while the row still grants membership, on either backend.
* Stores written by earlier versions are repaired at the first startup.

### Negative Consequences

* State-group, forward-extremity and recomputed `current_state` rows still commit separately from the
  event. A fault there leaves bookkeeping to repair, not a membership that grants access.
* An `invite` adopted from current state by reconciliation has no invite metadata (stripped state); the
  invitee sees the invite without the room summary.
