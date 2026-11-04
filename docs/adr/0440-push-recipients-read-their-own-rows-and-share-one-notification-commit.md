# Push recipients read their own rows and an event's notifications share one commit

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-04

Technical Story: Performance defect P1, per-recipient work on every message.

## Context and Problem Statement

`build_pending_push_deliveries` runs under `runtime.mutex` for every message and, for each local member, looked
up the member's `m.ignored_user_list` and `m.push_rules` by scanning the whole `account_data` vector, then wrote
the notification history row with its own committed INSERT followed by linear scans of the global
`notifications` vector. A message cost O(members x rows) plus one fsync per member.

## Decision Outcome

* `PersistentStore::account_data` and `notifications` each have an in-memory position index by user
  (`account_data_user_index`, `notification_user_index`), trusted only while `*_indexed_rows` equals the vector's
  size and every position names a row of the user asked for; otherwise a lookup scans, as for the state index
  (ADR-0344). Writers heal an index that is out of step before they use it; hydration rebuilds all indexes.
  Look a user's account data up with `find_account_data_content` or `for_each_user_account_data`; do not loop
  over `store.account_data` to find one user's row. Account-data rows are only appended or replaced in place, and
  notification rows are removed by moving the last row into the gap, so `store.notifications` has no meaningful
  order: read it through `list_notifications_for_user`, which sorts by stream ordering.
* `store_notifications` writes all of one event's upserts, and every prune they make necessary, in one
  transaction, and changes the in-memory mirror only after the commit. A failed commit therefore leaves memory
  equal to the database (CSAZ-10). The old per-row prune ran its DELETE with the result ignored, so a failed
  DELETE left the row in the database but gone from memory; that cannot now happen. A batch with an invalid row
  is refused whole.
* Rules, ignore lists, display names and tweaks stay per recipient. What is shared per event was already
  computed once before the recipient loop (parsed event, room facts, sender profile, state-event flags).
* `committed_transaction_count` and `ExaminedRows` (`account_data_rows_examined`, `notification_rows_examined`)
  are the test-facing cost counters.

## Considered Options

* Cache each user's parsed ruleset across events. Rejected: it needs invalidation on every writer of
  `m.push_rules`, `m.ignored_user_list` and the defaults, and a stale ruleset is a wrong notification.
* Keep `store_notification` per recipient and group commits some other way. Rejected: one INSERT per commit is the
  cost; a batch statement list is the existing transaction mechanism.
* Make the vector a map keyed by user. Rejected: hydration, `reload_room` and many tests write the vectors
  directly; the trust-while-in-step pattern keeps them correct.

## Links

* Related to [ADR-0344](0344-index-current-state-by-room-type-and-key-and-trust-it-only-while-in-step.md)
* Related to [ADR-0173](0173-cap-global-account-data-types-per-user.md)
