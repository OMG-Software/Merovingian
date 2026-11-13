# A room's state revision moves after the in-memory state write

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit C46,
`F-concurrency.send-join-plan-cache.state-revision-moved-before-ingest-commit-window`. Refines
[ADR-0624](0624-send-join-answers-are-planned-from-a-cached-room-wide-base.md).

## Context and Problem Statement

The send_join plan cache (ADR-0624) stamps a room-wide plan with `database::room_state_revision`, which "moves on every
write to the room's current state". `prepare_store_event_with_state` moved it when a state row was prepared, and
`apply_store_event_with_state` did not move it when the row was written to memory. Any reader between the two (in
`ingest_pdu_event` the commit window, while `runtime.mutex` was released) read the old row under the new revision and
cached a plan the stamp then kept valid: an in-place UPDATE changes neither the row count nor the roster the stamp also
checks.

When must the revision move so that no reader pairs a revision with older state than it names?

## Decision Drivers

* Invariant: the revision moves after every in-memory change to a room's current state, so no reader can stamp a
  revision newer than the state it read.
* Hold whatever lock a caller of prepare and apply holds or releases between them.

## Considered Options

* Move the revision in `apply_store_event_with_state`, after the in-memory row is written, and keep the prepare-time
  move.
* Move it only at prepare, and rely on callers never letting a reader in between.

## Decision Outcome

Chosen option: "Move the revision in `apply_store_event_with_state`, after the in-memory row is written", because it
makes the stamp right whatever a caller does between prepare and apply. ADR-0696 now keeps `runtime.mutex` across the
ingest commit of a state row, which closes this path too, but the stamp must not depend on every caller doing so.

* `apply_store_event_with_state` calls `note_room_state_changed` when the update carries a state row, after the row is
  written, as `apply_current_state` already did. A message's apply moves nothing.
* The prepare-time move stays: it costs one invalidation, and a revision that moves twice is never stale.

### Positive Consequences

* A plan stamped between a prepare and its apply is invalid once the apply has run.

### Negative Consequences

* A state write moves the revision twice, so a plan built from the state before is rebuilt once more than strictly
  needed. Plans are rebuilt per room on the next send_join only, so the cost is one rebuild per state write.

## Pros and Cons of the Options

### Move only at prepare

* Good, because one move per write.
* Bad, because it is right only while every caller holds `runtime.mutex` from prepare to apply, a rule nothing enforces
  and `ingest_pdu_event` broke.

## Links

* Refines [ADR-0624](0624-send-join-answers-are-planned-from-a-cached-room-wide-base.md)
* Relates to [ADR-0696](0696-an-ingest-that-writes-a-current-state-row-commits-under-the-runtime-lock.md)
