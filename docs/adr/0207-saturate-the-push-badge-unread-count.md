# Count the push badge in one bounded walk of the store, and saturate it

* Status: accepted
* Date: 2026-10-22
* Amended: 2026-10-23. The walk now relies on the stream-ordered event table of
  [ADR-0215](0215-the-event-table-indexes-by-id-and-by-stream-order-through-positions.md). It walks
  newest first in true stream order, stops once every room is settled, and looks thread parents up by
  event ID. The arrival-order caveats of the first version no longer apply (PR #523 review 5621537346).

Technical Story: PR #523 review (conformance audit wave 5): the push badge recount is unbounded
work under `runtime.mutex`

## Context and Problem Statement

Each notification sent to a Push Gateway carries `counts.unread`, "the number of unread messages a
user has across all of the rooms they are a member of". Push delivery computes it while it holds
`runtime.mutex`, once for every recipient with a pusher, for every notifying event. Since R15
(ADR-0205) the count evaluates the recipient's push rules on every unread event. It ran the exact
per-room walk once per joined room. Each walk scans every row of `store.events`, and the
read-marker and join-start lookups behind it scan the store again. So a single badge cost grew with
the store times the number of rooms, under the lock every request needs. That breaks the rule in
`src/homeserver/AGENTS.md` that work under the runtime lock is bounded by the request.

## Considered Options

* One walk of the store for the badge, newest first, stopping when every room is settled, with a
  fixed row budget
* Charge the existing per-room walks for every row they visit
* Bound only the events parsed and classified (the first version of this ADR)
* Keep an incremental per-user unread counter

## Decision Outcome

Chosen option: one bounded walk. `homeserver::count_push_badge` walks
`store.events.in_stream_order()` in reverse, newest first, across all of the user's joined rooms,
holding `runtime.mutex` throughout and writing nothing:

* Before the walk it reads the joined rooms (`memberships`) and resolves each read receipt's
  position with `EventTable::find_in_room`, as `read_markers_for` does. A receipt whose event is not
  stored in the room moves nothing.
* During the walk it records the user's own events (each reads its thread, ADR-0170), the user's
  membership changes (`member_transition`), and the events their rules notify for. Newest first in
  stream order, every own event and membership change above a candidate is met before it.
  Thread-parent lookups (`sync::event_thread_id`) are hash lookups and cost nothing.
* A room is **settled** once nothing below can change its count, and the walk skips its rows after
  that:
  * the walk has passed strictly below a non-join membership change, so every transition at or
    above it is known and the join start is pinned (`join_start_from`, `current_join_start`'s
    rule); or
  * with only joins met above, it meets a join at or below the room's unthreaded read marker. The
    join start is then at or below that marker, and `ReadMarkers::covers` treats the unthreaded
    marker as covering every thread, so nothing below can count.

  A join->join change (a profile change) leaves the join start undecided. The walk stops as soon as
  every joined room is settled.
* Every row visited costs one unit of `push_badge_row_budget` (10000), a backstop. When it runs out
  before every room is settled, the result is marked `capped`.
* An uncapped badge equals the sum of the exact per-room counts `sync::count_unread_by_thread` gives
  `/sync`. A test checks this for every budget over fixtures stored out of stream order.
* The badge saturates at `push_badge_unread_cap` (1000). Clients do not show counts that large in
  full ("99+", "999+"), so a saturated badge reads the same as an exact one.

`/sync` (`unread_notifications`, `unread_thread_notifications`) and sliding sync stay exact and
keep the per-room walk. The spec gives those counts no cap, and they run once per sync request for
the requesting user, not once per recipient per event.

### Equal stream orderings

`stream_ordering` is not unique, so the walk writes its comparisons deliberately. Rows strictly
above the lowest ordering visited (`lowest_visited`) have all been visited; rows equal to it may not
have been. A room is therefore settled only once the walk is strictly below its non-join change
(`>` on the pinned ordering). A capped room counts only candidates strictly above `lowest_visited`,
and its join start is taken only from membership changes strictly above it.

### The capped case

A capped walk is exact for every settled room. An unsettled room counts only candidates strictly
above `lowest_visited`. Every own event and membership change above such a candidate has been
visited, so no unvisited row can reduce its count. The room's join start comes from the membership
changes met above `lowest_visited`: exact if one is a non-join change, otherwise the earliest join
met, which is at or after the true start. A capped badge therefore never counts an event `/sync`
would not.

A room for which the walk met no membership change counts from the user's `memberships` row
instead, when it says `join` with a non-zero ordering. Every path that stores an accepted
`m.room.member` event for the user rewrites that ordering: local events, profile changes and joins
(with the event's ordering or one allocated after it), accepted federated events (with the event's),
and startup reconciliation (with a fresh one). So a `join` row's ordering is never before the start
of the current join, and counting only events after it can under-count but never over-count. A room
whose membership row ordering is 0 contributes nothing.

### Setup outside the walk

The setup is linear in the `memberships` and `receipts` tables, plus the
`PushRuleUnreadClassifier`'s room sources, once per badge. Nothing per room walks a whole table:

* The classifier gathers every room's facts at once, on its first room: one walk of `memberships`
  (joined counts, the user's rooms), one of the current `state` (power levels, create and the
  user's member event), and the user's profile. It looks the events those name up by ID.
* The receipt positions are resolved in one walk of `receipts`, with an ID lookup each.

`PushBadgeCount::table_walks` counts these walks, and a test holds it the same for 300 rooms as for
one. Bounding them by the user rather than the server needs per-user indexes on `memberships` and
`receipts`. That is a follow-up beyond ADR-0215, which indexes the events only.

### Positive Consequences

* The badge's walk visits at most 10000 rows under the lock, however large the store or the
  backlog, and usually far fewer: a user who has read their rooms is settled at their read markers.
* An uncapped badge is exact (to 1000), and a capped one never over-counts.

### Negative Consequences

* The setup walks are linear in the server's `memberships` and `receipts` tables, once per badge,
  until per-user indexes on them exist.
* A user with a deep unread backlog in a room they never left may exhaust the budget before the
  walk reaches their join, and the badge is then a lower bound. A room whose join was not reached
  counts from the membership row, missing the events before the user's latest membership change.
* The badge has a walk of its own beside `/sync`'s per-room walk. The two apply the same rules
  (`member_transition`, `join_start_from`, `sync::event_thread_id`, the receipt types of
  `read_markers_for`, the classifier), and tests hold them equal.

## Pros and Cons of the Options

### Charge the existing per-room walks for every row they visit

* Good, because it keeps one counting walk.
* Bad, because each room's walk restarts at row 0, so the budget is spent on other rooms' old
  events before any room's recent ones. On any real server the badge would be about 0.

### Bound only the events parsed and classified

* Good, because the badge stayed exact for most users.
* Bad, because rows filtered before the charge (other rooms, already read, not accepted) cost
  nothing, and the room loop kept going after the budget ran out, so the scan itself stayed
  unbounded (PR #523 review).

### An incremental per-user unread counter

* Good, because reading the badge would cost nothing.
* Bad, because it is new durable state that must change on every receipt, redaction, membership
  change and push-rule edit, and on thread-partitioned receipts. Every one of those paths could
  drift from what `/sync` reports.

## Links

* Refines [ADR-0205](0205-count-unread-notifications-by-push-rules-at-read-time.md) (counting by push rules)
* Depends on [ADR-0215](0215-the-event-table-indexes-by-id-and-by-stream-order-through-positions.md) (stream-ordered event table)
* Related to [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md) (push delivery caps)
