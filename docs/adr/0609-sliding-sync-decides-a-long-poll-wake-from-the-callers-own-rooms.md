# Sliding sync decides a long-poll wake from the caller's own rooms

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit, sliding-sync.long-poll-relevance-scan

## Context and Problem Statement

A sliding-sync request with `timeout>0` asks "did anything concern this connection since its cursor?" before
it parks. The answer walked every event newer than the cursor and tested each with `user_is_joined`, a linear
scan of `store.memberships`; the receipt and typing checks did the same. The cursor is 0 for a fresh
connection, so an account with no room made the server spend events x memberships under `runtime.mutex`
(measured: 4.5 s at 8000 events and 32000 memberships), before any park, so no in-flight budget applied.

## Considered Options

* One per-poll set of the caller's joined rooms, found through a per-user membership index, with a capped
  event walk
* Reuse `sync::room_access_index` as it was (still one scan of all memberships per poll)
* Per-room event index, so the check asks each joined room for events after the cursor

## Decision Outcome

Chosen option: the first.

* `PersistentStore::membership_user_index` holds the positions in `memberships` of each user's rows. It is
  kept and trusted exactly as `membership_room_index` is (ADR-0437): updated by `note_membership_row_appended`,
  rebuilt by `rebuild_membership_index` after hydration, `reload_room` and every erase, trusted only while
  `membership_indexed_rows == memberships.size()` and every position names a row of the user, and otherwise
  a reader scans. `for_each_user_membership_row` reads it and counts the rows it looked at in
  `membership_rows_examined`. `sync::room_access_index` and the push badge's room discovery use it too.
* The long-poll builds one set of the rooms the caller has a `join` row in (the meaning `user_is_joined`
  had), once per evaluation, and tests membership in O(1). A caller with no joined room is answered
  "nothing relevant" with no event walk. The receipt predicate uses the set, and the typing predicate
  iterates the typing map against it.
* The event walk, newest first and only past the cursor, stops at `sliding_sync_relevance_scan_rows` (2048).
  Reaching the cap counts as relevant: the poll is answered, not parked. This cannot lose a wake-up, because
  it errs towards answering. It cannot spin: the answer's `pos` is the current position, so the next poll's
  walk starts past those events and is short, and it parks (a test checks this). The cost of the cap is one
  extra answer after 2048 foreign events inside a single poll cycle.

A per-room event index was rejected as new durable-in-memory state for a check that only needs a bound. The
`device_list_changes`, `to_device_messages` and `account_data` checks beside these are left as they are:
they are separate findings with their own indexes.

## Links

* Builds on [ADR-0437](0437-the-sync-notifier-wakes-a-long-poll-for-its-own-user.md) and [ADR-0435](0435-the-event-table-keeps-a-per-room-index-in-stream-order.md)
