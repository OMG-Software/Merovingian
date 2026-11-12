# The per-request walks of a sync read device-list changes, filters, presence and room sources through indexes

* Status: Accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C34, variants (walks once per sync of a server-wide table).

## Context and Problem Statement

Besides the per-room scans of ADR-0654, a classic `/sync` walked four server-wide tables once per request, under the
runtime lock: `device_list_changes` (one row per observer and subject that ever shared a room, never deleted), `filters`
(every user's stored filters, for `find_filter` and the stored-filter summary), `presence_states` together with two passes
over every membership, and, in the push-rule unread classifier, every membership and every state row.

## Decision Drivers

* The work of one sync is proportional to the caller's own rows and their rooms' rows, never to a server-wide table.
* The existing row indexes (ADR-0603, ADR-0651) are the pattern: correct on every insert, replacement and delete and on
  load, trusted only while in step with the vector.

## Considered Options

* Three standing indexes (`device_list_observer_index` and `filter_user_index` as `RowGroupIndex`, `presence_user_index`
  as `RowKeyIndex`) with the classifier and the presence builder rebuilt on the existing membership and state indexes.
* Cache the per-request results.
* Leave the walks, since each is once per request.

## Decision Outcome

Chosen option: the first.

* `record_device_list_changes` finds the existing rows of the pairs a batch names through the observers' groups and
  erases them by moving the last row into the gap (the reader never relied on the vector's order: it compares stream
  positions); `collect_device_list_delta` and the sliding-sync wake check read the observer's rows through
  `for_each_observer_device_list_change`.
* `store_filter`, `find_filter` and the stored-filter summary read through `filter_user_index`
  (`for_each_user_filter`); `upsert_presence` and the presence builder through `presence_user_index`
  (`find_presence_state`). The presence builder collects the caller's joined rooms from their membership rows, each such
  room's joined members from its rows, then one index lookup per visible user, and emits in storage order as before.
* `PushRuleUnreadClassifier::ensure_room_sources` reads the user's membership rows, each of those rooms' membership rows
  for the joined count, and `find_current_state_event_id` for the power levels, the create event and the user's own member
  event.
* All three indexes are rebuilt by `rebuild_key_indexes` after hydration and rebuilt by their writer when found out of
  step. `device_list_rows_examined`, `filter_rows_examined` and `presence_rows_examined` count what the readers read.

### Negative Consequences

* A caller that edits `device_list_changes`, `filters` or `presence_states` directly (only tests do) leaves the index out
  of step; readers scan until the next write rebuilds it.
* The presence builder still reads every joined member of the caller's rooms: that is the set of users whose presence the
  caller is entitled to, and it is the caller's own rooms' rows.

## Links

* Builds on ADR-0603, ADR-0437, ADR-0344, ADR-0654, ADR-0651.
