# Bound the to-device queue in bytes per recipient

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-14, a to-device message could be any size up to the request body and was kept in memory and the database for every device it was sent to

## Context and Problem Statement

ADR-0117 bounded the to-device queue by rows (10000 per `(user, device)`) and age (7 days). Nothing bounded a
message's size, so one `PUT /sendToDevice` with a `*` device and a 1 MiB content stored one copy per device of the
target user, and 10000 of them per device was about 10 GiB. Every row is also held in the main process's memory
mirror and is loaded back at start-up. The spec states no size for a to-device message. It says only that a server
"should limit the number sent in each `/sync` response. 100 messages is recommended" (client-server API,
"Send-to-Device messaging").

## Considered Options

* Refuse a message over a size limit, and evict a recipient's oldest rows past a byte budget, both configurable
* Only a per-message limit
* Cap each `/sync` response at 100 to-device events and rely on that

## Decision Outcome

Chosen option: "Refuse a message over a size limit, and evict past a byte budget".

* `server.client_api.max_to_device_message_bytes`, default 65536 (the size of a PDU), range 1 to 16,777,216: the
  limit on one message's serialised content. A client `PUT /sendToDevice` with any message over it is refused with
  `413 M_TOO_LARGE` and nothing is queued or recorded. An inbound `m.direct_to_device` EDU drops that one message and
  keeps the others: EDUs are best-effort and the sending server cannot be told which message was refused.
* `server.client_api.max_to_device_bytes_per_user_device`, default 16,777,216 (16 MiB), range 1 to 1,073,741,824: a
  recipient whose queued content bytes would pass it loses its oldest rows first, as the row cap does. A message
  larger than the budget is refused (the config validator rejects a message limit over the budget).
* Zero in the store disables a bound, as it does for the row cap; the config validator does not allow zero.
* The bytes counted are the rows' `content_json` sizes. The byte total of a recipient is computed from its rows each
  time a batch is prepared (`to_device_queue_bytes` does the same for tests), never kept as a counter, so it cannot
  drift from the rows after an eviction, an acknowledgement, a failed commit or hydration.

The per-`/sync` cap of 100 was not added. The spec says "should", but the classic `/sync` `next_batch` carries one
shared stream position for rooms, to-device and account data. Stopping after 100 to-device events would need a
to-device-only position in the token, or the response would acknowledge events it did not send. The queue is now
bounded in bytes (at most the budget per device in one response), which is what the cap was for. The time-to-live
purge also stays a side effect of enqueue and drain: no periodic job exists to carry it, and a new thread for it was
not justified by a queue that is now bounded in bytes.

### Positive Consequences

* A recipient's queue holds at most the byte budget however many rows or devices a sender names.

### Negative Consequences

* A message that is legitimately larger than 64 KiB is refused; no client sends one today (room keys and verification
  messages are a few KiB). An operator can raise the limit.
* A `*` send to a user with many devices still stores one copy per device, bounded by the delivery cap (ADR-0336).

## Links

* Extends [ADR-0117](0117-bound-to-device-queues-by-recipient-count-and-age.md)
