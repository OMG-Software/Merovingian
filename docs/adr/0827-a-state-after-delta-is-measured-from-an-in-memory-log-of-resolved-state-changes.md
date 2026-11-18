# A `state_after` delta is measured from an in-memory log of resolved state changes

* Status: accepted
* Date: 2026-11-17

Technical Story: review of 1.1.1, https://github.com/OMG-Software/Merovingian/pull/595#discussion_r4593957508

## Context and Problem Statement

[ADR-0819](0819-a-state-after-delta-compares-the-two-states.md)
measured an incremental `state_after` from the state recorded for the newest event at or below `since`. A client is
told the room's *resolved* state, which on a forked room is not that event's recorded state. Take a fork at `since`
whose resolution picks branch A while the newest event records branch B:

1. The client is told A.
2. Resolution later moves the key to B.
3. The delta compares B with B and sends nothing.

The client keeps A for ever, and `state_after` exists so that a client can stop reading state from the timeline.

A backfilled event ordered at or below `since` can stand in for the anchor in the same way. The left-room delta had the
same baseline.

How can a delta be exact against what the client was told, at the cost rules of `src/sync/AGENTS.md`?

- A room with no news costs nothing.
- There is no whole-state read on the common path.
- There is no per-request scan of a room's rows under `runtime.mutex`.

## Decision Drivers

* The delta must equal the difference between the state told at `since` and the state told now, for every graph shape.
* A window of messages must read no state.
* Every writer of current state already runs under `runtime.mutex` in the main process, as does every sync.

## Considered Options

* Store each response's state per token (refused in ADR-0819 for its cost)
* Send the whole state whenever the room is forked
* A persisted table of state changes (migration 004)
* An in-memory log of resolved state changes, keyed by the sync position from which a client sees each one

## Decision Outcome

Chosen option: the in-memory log, `database::StateChangeLog` (`PersistentStore::state_change_log`), read through
`sync::resolved_state_at`, `sync::resolved_state_changes` and `sync::resolved_state_event_at`.

* **What is recorded.** Every change to a room's current state in the main process is recorded: room, key, previous
  event and new event.
  - Every such change goes through one of four store functions, and each records: `apply_store_event_with_state`,
    `apply_current_state`, `store_state` and `remove_current_state_rows`.
  - `apply_room_snapshot` forgets the room instead (a reload replaces the room's state wholesale).
  - The federation worker never starts the log, so it records nothing.
* **Where a change is filed.** A change is filed at the stream ordering of the event whose storing made it, raised to
  one above the highest position a sync has answered at (`note_served`, called where `sync_json` fixes
  `sync_position`).
  - So no change is ever filed at or below a position a client was already told about.
  - The state as of a served position is therefore fixed once served: the current state, with each key changed above
    the position put back to the value its first such change replaced.
  - A backfilled event ordered below `since` is filed above it.
* **Why the delta is exact.** The state told at `since` and the state told now are both read from this one record, so
  their difference is exact. Specifically:
  - A key that state resolution moved back is found.
  - A key that changed and changed back is not sent.
  - A key removed from the state is not sent, since `state_after` cannot express a removal.
  - The whole-state answers (an initial sync, `full_state=true`, a join in the window) are the same rebuilt state, so
    a later delta starts from what was really said.
  - A lazy-loaded sender's member as of the position is looked up the same way.
* **Left rooms.** A left room's delta is the state readable as of the leave (`room_read_access_for`, unchanged) minus the
  state told at `since`.
* **News check.** `select_sync_rooms` counts a logged change above `since` as news for a `state_after` client, because
  a change with no event of its own in the room is still a change.
* **Cost.**
  - A delta reads the room's changes above `since`, counted in the log's `rows_examined`, plus one lookup by key per
    key they name: nothing for a window of messages.
  - `has_change_after` is one map lookup.
  - Rebuilding a whole state reads the room's state rows once, which is what the whole-state answers already did.
* **What is not covered.** The log covers a position only above the position the process started at, and only at or
  above a room's horizon. A position outside that falls back as follows:
  - A `since` at or below the start was answered by an earlier process, or comes from a database restored or upgraded
    from one, so it is never trusted for a delta. The room's whole resolved state is sent once (an update the client
    already holds is harmless), and the next sync is a delta again. Upgraded databases need nothing more.
  - When the log does not cover the position itself, the state ADR-0247 reads is sent. A delta from that position is
    then never taken, so the two cannot disagree.
* **Bounds.**
  - At most 1,024 changes per room and 65,536 in all. Past either bound the oldest change is dropped.
  - Dropping a room's change raises that room's horizon: a `since` below it is not covered, and the room's whole
    state is sent once.

This supersedes the part of ADR-0819 that chose the baseline and the chain walk (`state_changes_along_chain`, now
removed). ADR-0819's lazy-loading rules stand.

### Positive Consequences

* The delta is exact against what each response said, for forks, resolutions that move a key back, and backfill.
* A window of messages costs nothing. No migration, and no write to any transaction.

### Negative Consequences

* After a restart, the first `state_after` sync of each room with news sends that room's whole state once.
* A change made with no event that raises the stream (for example a state group recorded later for an old event) is
  filed above the last served position, and reaches clients when the stream next moves. As before, this happens as soon
  as any event is stored anywhere on the server. If the process stops first, the change waits for the room's next
  event, which is then sent with the room's whole state.
* The log uses memory: at most 65,536 changes of a few event IDs each.

## Pros and Cons of the Options

### Store each response's state per token

* Bad, because it costs a room's whole state per response, per device.

### Send the whole state whenever the room is forked

* Bad, because a room that stays forked (common over federation) would send its whole state on every sync.

### A persisted table of state changes (migration 004)

* Good, because a restart would not cost one whole state per room.
* Bad, because it needs a migration on both backends, a row in every writer's transaction (including state
  resolution's corrections), its own bound and pruning, worker classification and an upgrade answer. The answer for an
  upgraded database would still be "send the whole state once", so the gain is only the first sync after each restart.

### An in-memory log

* Good, because it is exact, costs nothing for a window of messages, and touches no schema.
* Bad, because it starts empty at every start-up (see Negative Consequences).

## Links

* Supersedes the baseline and the chain walk of [ADR-0819](0819-a-state-after-delta-compares-the-two-states.md)
* Keeps the access rule of [ADR-0820](0820-a-left-rooms-state-after-stops-at-what-the-user-may-read.md)
* Relates to [ADR-0247](0247-no-sync-position-passes-a-stream-ordering-still-being-committed.md)
