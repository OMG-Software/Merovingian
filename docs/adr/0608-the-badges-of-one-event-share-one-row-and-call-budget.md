# The badges of one event share one row and call budget

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, push-badge-count.ten-thousand-row-walk-per-recipient-under-runtime-mutex

## Context and Problem Statement

[ADR-0207](0207-saturate-the-push-badge-unread-count.md) bounds one badge to 10000 event rows, but
`build_pending_push_deliveries` computes a badge for every recipient with an http pusher, under
`runtime.mutex`. One message to a room with N such recipients cost N full walks (measured: 983 ms for nine
recipients, against 10 ms without pushers). The bound was per recipient, not per event.

## Considered Options

* An incremental per-user unread counter
* A budget shared by all the recipients of one event
* Compute the badge off the lock

## Decision Outcome

Chosen option: a `PushBadgeBudget` per event, shared by its recipients.

* It holds `push_badge_event_row_budget` (10000) rows and `push_badge_calls_per_event` (16) calls.
  `count_push_badge(runtime, user, ruleset, budget)` takes one call, walks at most
  `min(rows_left, push_badge_row_budget)` rows and charges the rows it visited.
* A recipient who finds either spent is given no count: `count_push_badge` returns nullopt, the
  notification's `PushGatewayCounts::unread` is absent and the request omits `unread` (the spec's counts
  are optional), so the client keeps its last badge. The notification is stored and retried as built, so the
  omission survives `PushRetry`. A badge that started within budget and saturated or capped keeps ADR-0207's
  behaviour. An earlier draft sent 1 to such a recipient; in a room with more than 16 pusher recipients the
  same members, in member order, would have had their real badge overwritten with 1 on every event, so
  it was rejected.
* The recipients draw on the budget starting at `stream_ordering % recipient_count`
  (`push_badge_draw_start`), wrapping, so when the budget runs short the members left without a count change
  from event to event. Nothing in the recipient loop depends on order: each recipient's checks and caps
  are its own, the history rows are committed together after the loop, and delivery dispatch groups by
  recipient (the in-flight cap that drops later deliveries now drops a rotating set too).
* `EmailPush.cpp` counts one recipient per lock hold with a fresh single-call budget, so it is already
  bounded by one walk. `PushRetry.cpp` calls no badge code: it resends the notification as built, with the count it carried.

The incremental counter was rejected again, for the reason in ADR-0207: it is new durable state that has to
follow every receipt, redaction, membership change, push-rule edit and thread relation, and any path that
drifts from `/sync` shows a wrong badge for good. Computing off the lock was rejected because the walk reads
the store the lock protects.

### Residual

The setup walks of one call (the memberships, the receipts, the classifier's state walk) stay linear in the
size of those tables. They now run at most 16 times per event instead of once per recipient. Bounding them
by the user needs per-user indexes on receipts and the state; the membership walk uses the per-user
membership index of [ADR-0609](0609-sliding-sync-decides-a-long-poll-wake-from-the-callers-own-rooms.md).

### Negative Consequences

* In a room with more than 16 pusher recipients, or recipients with deep backlogs, those past the budget are
  sent the event without a count, which a client may show as no change to its badge.

## Links

* Refines [ADR-0207](0207-saturate-the-push-badge-unread-count.md)
