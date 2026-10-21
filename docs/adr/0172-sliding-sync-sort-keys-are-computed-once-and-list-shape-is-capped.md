# Sliding-sync sort keys are computed once per request, and the shape of the lists is capped

* Status: accepted
* Date: 2026-10-21

## Context and Problem Statement

`sync::compute_room_list` sorts a user's joined rooms for each MSC4186 list with
`std::stable_sort` while the request holds the global runtime lock. The `by_recency` and
`by_name` keys were computed inside the comparator, so every one of the O(N log N) comparisons
scanned the whole event store (JSON-parsing each in-room event when `bump_event_types` was set).
The number of lists, the `sort` array and `bump_event_types` were uncapped. One authenticated
request could therefore hold the lock for seconds to minutes and stall every other client and
federation callback (security audit run-1, `sp01.sliding-sync-sort-comparator-store-scan`,
HIGH). 0.12.30 had already precomputed `by_notification_count` for the same reason.

## Considered Options

* Keep per-comparison keys and only cap the request.
* Compute every sort key once per room before the sort, and cap the request shape with fixed
  limits.
* The same, with the new limits as configuration keys like `sliding_sync_max_room_subscriptions`.

## Decision Outcome

Chosen option: "compute every sort key once per room, cap the shape with fixed limits", because
caps alone leave each comparison a store scan, and precomputation alone leaves a request free to
multiply its cost by thousands of lists. The two keys this decision moves out of the comparator
now cost one pass over the store per list: `by_recency` walks `store.events` newest first and
does not parse an event that cannot beat its room's current maximum; `by_name` makes one pass
over `store.state` and one over `store.events`. `by_notification_count` was already computed once
per room (0.12.30), but each room's count is still its own walk over the store, and enumerating
the joined rooms and applying the list's filters also do per-room work. The comparator only looks
keys up.

The rule for future code: **a sliding-sync sort key is computed before the sort, never inside the
comparator.**

`SlidingSyncLimits` caps lists at 32, sort keys per list at 3 (MSC4186 defines three, and
repeating one changes nothing), and `bump_event_types` per list at 64.
`sliding_sync_request_limit_violation` rejects a request over any cap with 400
`M_INVALID_PARAM`. These are fixed policy, not configuration. Unlike the subscription and
`required_state` caps, which bound legitimate working-set size and may need tuning, these bound
the request's shape. Known clients use one or two lists, a few sort keys and about ten bump types,
so there is nothing for an operator to tune, and a config key would only be a way to remove the
bound.

### Positive Consequences

* The sort itself no longer multiplies store work by the number of comparisons:
  `by_recency` and `by_name` cost one pass over the store per list, whatever the room count.
* The 32-list cap bounds how many times a request repeats the per-list work.

### Negative Consequences

* A client sending more than 32 lists or 64 bump types gets 400 `M_INVALID_PARAM` instead of
  being served.
* Per-room store work remains under the runtime lock: `by_notification_count` (one walk per
  room), the joined-room enumeration and the list filters. A list's cost still grows with the
  user's joined-room count times the store size for those parts; this decision bounds the
  comparator, not them.
