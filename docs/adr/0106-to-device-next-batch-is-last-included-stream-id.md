# to_device next_batch is the last included stream ID

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-10-05

Technical Story: security audit finding on `fix/audit-medium-0.12.16`

## Context and Problem Statement

The MSC4186 sliding-sync `to_device` extension reported `next_batch` as the
global sync-stream watermark (`store.next_sync_stream_id`). `drain_to_device_messages`
deletes every device-targeted row whose `stream_id` is `<=` the request's `since`
argument. Because the global watermark can run ahead of the newest queued
message (e.g. due to presence or account-data updates), a client that used the
returned `next_batch` would implicitly acknowledge rows it had never received,
which meant:

1. A truncated or lost response could permanently lose messages: the next poll
   would delete them rather than replay them.
2. The continuation token advanced past events that were not included in the
   response, breaking pagination.

## Decision Drivers

* `next_batch` must only advance past messages actually delivered to the client.
* A lost or truncated response must be replayable from the same position.
* Delete-on-acknowledgement must remain bounded and correct.
* The change must not regress existing sliding-sync clients that pass the
  returned token back as `since`.

## Considered Options

1. **Keep `next_batch` as the global watermark (status quo).** Simple, but
   acknowledges undelivered rows and breaks pagination on truncation or loss.
2. **Set `next_batch` to the stream ID of the last message included in the
   response.** Empty responses keep the previous position. This makes
   `drain_to_device_messages` delete only rows the client has explicitly
   acknowledged, matching delete-on-ack semantics.
3. **Track per-device highest acknowledged stream ID separately.** Would allow
   finer-grained acknowledgement but adds state and complexity with no spec
   requirement for it.

## Decision Outcome

Chosen option: **option 2**. `build_to_device` now derives `next_batch` from the
stream ID of the last to-device message actually serialized into the response.
If the response contains no messages, `next_batch` is the input `since` value so
the client does not regress or jump ahead spuriously.

### Positive Consequences

* Lost or truncated responses replay from the same position.
* Only delivered device-targeted rows are deleted from the queue.
* The pagination contract is consistent with the MSC4186 `next_batch` intent.

### Negative Consequences

* Wildcard/broadcast (`*` or empty `target_device_id`) rows are still not
  deleted per-device; they continue to be filtered by `since` only. This is a
  pre-existing design choice and is unchanged.
* If a client holds an old global-watermark token from before this change, the
  first request after upgrade will acknowledge all older device-targeted rows.
  This is acceptable for an unstable MSC4186 endpoint.

## Links

* `src/sync/sliding_sync_extensions.cpp` — `build_to_device`
* `tests/unit/test_sliding_sync_to_device_pagination.cpp`
