# The to-device queue is restored to numeric stream-id order after hydration

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`to_device_messages.stream_id` is a TEXT column on both backends, so `ORDER BY stream_id` returns "10" before "9" and,
on PostgreSQL, depends on the collation. After a restart the in-memory queue held rows 10, 11, 9. The sliding sync
`to_device` extension sends the first `limit` rows and sets `next_batch` to the last one it sent; the next request then
treats every id at or below it as acknowledged and deletes it, so row 9 was lost, and with it a room key.

## Decision Outcome

The order is restored in one place both backends call, `database::sort_to_device_messages`, after hydration (as
`sort_appservice_outbox` already does), not by changing the SQL. `drain_to_device_messages` returns its rows ascending
whatever order the store holds, and the extension sorts again before taking its page, so `next_batch` can never pass a
row that was not sent. Any new code that pages through the queue relies on ascending order and must not assume the
store's.

`account_data`, `room_account_data`, `device_list_changes` and `presence_state` also load with `ORDER BY stream_id` but
are harmless: account data and presence are keyed upserts, and `collect_device_list_delta` compares stream ids
explicitly rather than trusting row order.
