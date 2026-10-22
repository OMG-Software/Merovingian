# Saturate the push badge's unread count, and bound the walk that computes it

* Status: accepted
* Date: 2026-10-22

Technical Story: PR #523 review (conformance audit wave 5): the push badge recount is unbounded
work under `runtime.mutex`

## Context and Problem Statement

Each notification sent to a Push Gateway carries `counts.unread`, "the number of unread messages a
user has across all of the rooms they are a member of". Push delivery computes it while it holds
`runtime.mutex`, once for every recipient with a pusher, for every notifying event. Since R15
(ADR-0205) the count parses every unread event in every joined room and evaluates the recipient's
push rules on each. A recipient with a large unread backlog therefore makes every event in their
rooms cost work proportional to that backlog, under the lock every request needs. That breaks the
rule in `src/homeserver/AGENTS.md` that work under the runtime lock is bounded by the request.

## Considered Options

* Saturate the badge count, and stop the walk once it saturates or has examined a fixed number of
  events
* Keep an incremental per-user unread counter
* Saturate only the result, and keep walking every unread event

## Decision Outcome

Chosen option: saturate and bound the walk. `homeserver::push_badge_unread_count` counts with a
`sync::UnreadScanBudget`:

* It stops counting at `push_badge_unread_cap` = 1000 notifications and reports 1000. The value is
  a badge, and clients do not show a count that large in full ("99+", "999+"), so a saturated
  badge reads the same as an exact one.
* It parses and classifies at most `push_badge_unread_examined_cap` = 4000 unread events across
  all rooms. Events the rules do not notify for (membership changes, edits, notices) are examined
  without counting, so the notification cap alone would not bound the work. A count that runs out
  of examinations first reports the notifications it found, a lower bound. With the defaults
  notifying for every message, that needs over 3000 unread non-notifying events.
* The budget is checked before each event is parsed, so the walk stops; it does not finish the room
  and discard the result.

`/sync` (`unread_notifications`, `unread_thread_notifications`) and sliding sync stay exact. The
spec gives those counts no cap, and they run once per sync request for the requesting user rather
than once per recipient per event. They use the same walk, `count_unread_by_thread_within`, with an
unlimited budget.

### Positive Consequences

* The badge's cost per recipient per event is bounded by a constant number of classified events,
  plus the linear room filter over the store, as before.
* There is one counting walk, with no second implementation.

### Negative Consequences

* A recipient with over 1000 unread notifications sees a badge of 1000.
* A recipient with over 3000 unread events their rules do not notify for can see a badge lower than
  the exact count.

## Pros and Cons of the Options

### An incremental per-user unread counter

* Good, because reading the badge would cost nothing.
* Bad, because it is new durable state that must change on every receipt, redaction, membership
  change and push-rule edit, and on thread-partitioned receipts. Every one of those paths could
  drift from what `/sync` reports.

### Saturate only the result

* Good, because it is the smallest change.
* Bad, because the walk still parses and classifies the whole backlog, which is the cost under the
  lock.

## Links

* Refines [ADR-0205](0205-count-unread-notifications-by-push-rules-at-read-time.md) (counting by push rules)
* Related to [ADR-0028](0028-drop-push-deliveries-at-the-concurrency-cap.md) (push delivery caps)
