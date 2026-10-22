# Count the push badge in one bounded pass over the store, and saturate it

* Status: accepted
* Date: 2026-10-22

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

* One pass over the store for the badge, charging every row visited, with a fixed row budget
* Charge the existing per-room walks for every row they visit
* Bound only the events parsed and classified (the first version of this ADR)
* Keep an incremental per-user unread counter

## Decision Outcome

Chosen option: one bounded pass. `homeserver::count_push_badge` visits `store.events` once, newest
row first, across all of the user's joined rooms:

* Every row visited costs one unit of `push_badge_row_budget` (10000), before any filter. That
  includes the rows a thread-parent lookup scans (`sync::event_thread_id_within`). There is no early
  stop. When the budget runs out, the pass ends and the result is marked `capped`.
* The joined rooms and the user's read receipts are loaded once, before the pass. During it, the
  pass records each receipt's target position, the user's own events (which read their thread,
  ADR-0170), the user's membership changes (`member_transition`), and the events their rules notify
  for. A filter or position check that depends on another row is applied afterwards: the receipt
  positions, the join start (`join_start_from`, `current_join_start`'s rule), and thread coverage.
  The result therefore does not depend on row order.
* When the pass visits every row, the badge equals the sum of the exact per-room counts
  `sync::count_unread_by_thread` gives `/sync`. A test checks this over a join->join profile
  change, a leave and rejoin, a backfilled pre-join event and a rejected event.
* The badge saturates at `push_badge_unread_cap` (1000). Clients do not show counts that large in
  full ("99+", "999+"), so a saturated badge reads the same as an exact one.

`/sync` (`unread_notifications`, `unread_thread_notifications`) and sliding sync stay exact and
keep the per-room walk. The spec gives those counts no cap, and they run once per sync request for
the requesting user, not once per recipient per event.

### The capped case

`store.events` is not stream-ordered. Hydration selects without `ORDER BY`, PostgreSQL moves rows
it updates, and commits land out of stream order. A capped pass therefore covers whichever rows it
reaches, not necessarily the newest, and its badge is a lower bound that can miss recent unread
events on a large store.

A room whose join event a capped pass did not reach counts from the user's `memberships` row
instead, when it says `join` with a non-zero ordering. Every path that stores an accepted
`m.room.member` event for the user rewrites that ordering: local events, profile changes and joins
(with the event's ordering or one allocated after it), accepted federated events (with the event's),
and startup reconciliation (with a fresh one). So a `join` row's ordering is never before the start
of the current join, and counting only events after it can under-count but never over-count. It
under-counts the events between the true join and the latest membership change, such as a profile
change. A room whose join and membership row are both unusable contributes nothing. A pass that is
not capped never uses the row, so it stays equal to `/sync`.

A capped pass skips whatever it cannot prove: a room whose unthreaded receipt target it did not
reach, a thread whose receipt target it did not reach, a room with an own event whose thread it
could not determine, and an event whose thread it could not determine. What it cannot rule out
without visiting every row is an unvisited row, stored out of stream order, that would have reduced
the count: an own event in the same thread, or a membership change, with a higher stream ordering
than a counted event. The tests cover rows stored out of order, and check that a capped badge never
exceeds the exact count.

Per-room setup is not yet bounded by the row budget either. The classifier's room facts (power
levels, display name) and its history-visibility indexes are built from the store once per room and
once per badge.

**Follow-up:** store-wide indexes, by stream ordering and by event ID. They let the pass start at
the newest rows and stop at each room's read marker or join start, make thread-parent lookups exact
and cheap, and bound the per-room setup. They are a store-wide change, deferred from this PR, like
room-scoped indexing.

### Positive Consequences

* A badge costs at most 10000 row visits under the lock, however large the store or the backlog.
* While the store is within the budget, the badge is exact (to 1000).

### Negative Consequences

* On a store larger than the budget the badge is a lower bound until the indexes land. Rooms whose
  join was not reached count from the membership row, missing the events before the user's latest
  membership change.
* The badge has a pass of its own beside `/sync`'s per-room walk. The two apply the same rules
  (`member_transition`, `join_start_from`, `event_thread_id_within`, the classifier), and a test
  holds them equal.

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
* Related to [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md) (push delivery caps)
