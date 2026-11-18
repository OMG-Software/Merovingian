# A `state_after` delta compares the two states, and every change it finds is sent under lazy-loading

* Status: accepted (the baseline at `since` and the chain walk are superseded by [ADR-0827](0827-a-state-after-delta-is-measured-from-an-in-memory-log-of-resolved-state-changes.md); the lazy-loading rules stand)
* Date: 2026-11-16

## Context and Problem Statement

An incremental `state_after` holds the state that differs between `since` and the response's position. State resolution can
move a key back to an older event: no event of the window is about that key, and its current event is older than `since`.
This is the case `use_state_after` exists for, since a client reading `state` and `timeline` cannot see it. `/sync` runs under
`runtime.mutex` for every syncing user, so the cost matters as much as the answer
([ADR-0435](0435-the-event-table-keeps-a-per-room-index-in-stream-order.md),
[ADR-0436](0436-an-event-is-judged-for-ignored-senders-without-parsing-it-first.md)).

## Considered Options

* List the state events in the window and send each key's current value (rejected: misses a key moved back)
* Read both whole states for every room with a new event (rejected: a room's state, twice, per user, per message)
* Compare state groups: nothing when they are one group, the rows between them on an unforked delta chain, and both whole
  states only when the chain does not connect them

## Decision Outcome

Chosen option: compare state groups (`joined_state_changes` in `ClientServerRuntime.cpp`, `state_changes_along_chain` in
`StateGroupLookup.cpp`).

* A room with no event above `since` costs one look at its newest row and sends nothing.
* The state at `since` is the recorded state of the newest event at or below it (`state_anchor_event`, found by a binary
  search of the room's stream-order index, so the rows a long absence missed cost nothing; a test reads
  `state_anchor_rows_examined`). With one forward
  extremity, at or below the position, the current state is that event's recorded state, so the two points are two groups:
  the same group for a window of messages (no rows read), otherwise the rows between them
  (`state_changes_along_chain`, which never reads a snapshot's rows). The extremity comes from the room's own tips
  (`ForwardExtremityTable::tips_of_room`), never from a walk of every room's.
* A fork, a snapshot between the two points (at most `max_state_group_delta_depth` hops apart) or an unreadable chain falls
  back to the state at the position minus the state at `since`, the room's own rows. An event is the value of one key, so
  subtracting event IDs finds exactly the keys that differ.
* With no recorded state at `since`, all the state at the position is sent: an update the client holds is harmless.

Lazy-loading: `state_after` carries, besides all non-member changes, every member event in the delta (never redundant, in
the timeline or not, about a sender or not, since the client takes no state from the timeline), and each timeline sender's
member event as of the position, by key and subject to redundancy (`member_event_at_position`, with the cost rule of
[ADR-0454](0454-a-senders-member-is-looked-up-by-key-never-by-scanning-the-room-state.md)). The user's own member event on
an initial sync, `full_state=true` or a join in the window is sent even when the timeline carries the join, which
[ADR-0452](0452-the-state-filter-selects-lazy-loaded-members-on-sync.md) allows only for `state`.

The tracker's rules ([ADR-0450](0450-lazy-loaded-members-are-skipped-only-when-the-since-token-acknowledges-them.md)) are
unchanged, and it is shared with `state` responses under the same stream key. It compares event IDs: a client that switches
modes either holds the event named or is sent it again. What `state_after` sends is recorded as what `state` sends is.

### Consequences

* The state at `since` is what was recorded for one event, not what the response carrying that token said. If the graph was
  forked at `since`, the resolved state the client was told can differ from that recorded state, and a key that resolution
  later flipped to the recorded value is not sent. A backfilled event ordered at or below `since` can stand in the same way.
  Storing each response's state per token would close this and was refused for its cost; `full_state=true` repairs a client.
* A window that crosses a snapshot reads both whole states, about once per `max_state_group_delta_depth` state changes. It
  sends only what differs.
* A key that changed and changed back within the window may be sent, with the value the client already holds.
