# An event this server places commits with its bookkeeping in one transaction

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-25

Technical Story: 0.12.48, PR #533 review: a failure part-way through storing a local event or a
federated join left the earlier writes committed

## Context and Problem Statement

Storing an event this server places itself (a local event, or the join event of a federated
join) took up to five transactions (ADR-0064): the event row with its `current_state` row and
membership projection (DB-4), the after-state group, the event's mapping to that group, the
forward-extremity change, and the `current_state` rows the resolution of the new extremities
changed. Each committed on its own. A refusal part-way through left the earlier ones behind:

* A local event whose `current_state` write failed was stored, mapped and made the room's tip,
  while the client was told 500 and could retry it.
* A federated join whose state group could not be written left the user's membership `join`
  and the join event stored, with no state group and no forward extremity, so the next local
  event in the room had nothing to be built on.

`store_local_event`'s header said every failure was a hard failure that left no broken
bookkeeping. It did not.

How should those writes be made to succeed or fail together?

## Decision Drivers

* A refused write must leave the store as it was: no event, membership, group, mapping or tip.
* The in-memory store mirrors only what is committed, as every store function already does.
* One code path for "store an event this server places", not one per caller.
* No new backend capability: `commit_persistent_transaction` already commits a list of
  statements atomically on SQLite and PostgreSQL.

## Considered Options

* Prepare every write, commit them in one transaction, then mirror them in memory.
* Keep the separate commits and undo the earlier ones when a later one fails.
* Leave it, and document that a 500 here may have stored the event.

## Decision Outcome

Chosen option: "Prepare every write, commit them in one transaction, then mirror them in
memory", because it is the only option under which a refusal cannot leave partial state.

`homeserver::store_event_with_bookkeeping` (`state_bookkeeping.cpp`) prepares the event
(`prepare_store_event_with_state`), its after-state group (`prepare_state_group`), the mapping
(`prepare_event_state_group`), the forward-extremity change
(`prepare_forward_extremities_update`) and every `current_state` change
(`prepare_current_state`), commits them as one transaction, and only then applies each to the
in-memory store. The resolution behind the `current_state` changes runs before the commit, with
the event standing in for itself: it is not yet in `store.events` or any recorded group.
`store_local_event` and the federated join both call it. The single-step functions
(`create_or_reuse_state_group`, `set_event_state_group`, `update_forward_extremities`,
`store_state`) are now their prepared form, a commit and the apply, so the two paths cannot drift.

A federated join's after-state is now one full snapshot group. Before, it was a delta on a
separate `join-snapshot:` group holding the state before the join; a delta cannot be prepared
against a parent that is itself only prepared, and nothing read the before-join group.

### Positive Consequences

* A local event or federated join that answers 500 has written nothing (tests assert it).
* The source-tree guard (`test_store_event_choke_point.cpp`) now also reviews every
  `prepare_store_event_with_state` caller, since a caller that commits those statements
  without bookkeeping bypasses ADR-0064 as surely as `store_event_with_state` does.

### Negative Consequences

* What follows the commit stays outside it: `finish_local_membership`'s device-list changes,
  push and appservice queueing. They are derived from the stored event and were never in the
  event's transaction.
* Inbound PDUs (`ingest_pdu_event`) keep their separate commits: the PDU is committed first,
  with the runtime lock released, and its state group recorded after (ADR-0064's documented
  trade-off). Making that path atomic is a separate change.
* A join's group no longer shares its rows with a before-join group, so it stores the full
  state where it used to store the before-join snapshot plus a one-row delta: the same rows,
  in one group instead of two.

## Pros and Cons of the Options

### Undo the earlier commits on failure

* Good, because it is a smaller change.
* Bad, because an undo is itself a write that can fail, and between the commit and the undo
  another reader (sync, the federation worker's reload) can see the partial state.

### Leave it and document it

* Bad, because a client that retries a 500 can store the same message twice, and a failed
  join leaves a user joined to a room this server cannot send into.

## Links

* Refines [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md): local and
  join bookkeeping commit with the event, not after it.
* Builds on [ADR-0225](0225-a-local-event-falls-back-to-the-newest-forward-extremity-when-their-state-cannot-be-resolved.md),
  whose retired extremities leave in the same transaction.
