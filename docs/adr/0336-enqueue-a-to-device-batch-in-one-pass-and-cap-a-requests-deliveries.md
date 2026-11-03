# Enqueue a to-device batch in one pass, and cap a request's deliveries

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run-2 F-13, `PUT /sendToDevice` cost O(queue x recipients squared) under `runtime.mutex`

## Context and Problem Statement

`prepare_to_device_enqueue` walked the whole shared `to_device_messages` vector for every message of a batch, and for
every row first scanned the batch's evictions before testing the row's recipient. A request naming M devices at their
row cap cost about Q x M^2 / 2 comparisons, and `apply_to_device_batch` repeated Q x M. The client path capped
nothing: a `*` send expanded to every device of the target user, and the body cap is the only bound on how many
users and devices one request names.

## Considered Options

* Index the queue by recipient in `PersistentStore`
* Build the batch's recipient queues in one pass over the vector, and hash the evictions
* Test the recipient first and keep the scans

## Decision Outcome

Chosen option: "Build the batch's recipient queues in one pass over the vector, and hash the evictions".

`enqueue_to_device_messages` and the client-transaction variant first name the batch's recipients, then walk
`store.to_device_messages` once and gather only those recipients' rows into per-recipient queues (stream id, age,
bytes). Each message then evicts from its own recipient's queue only. `apply_to_device_batch` and the drain's purge
remove rows with a hash of evicted stream ids confirmed against the full key, one pass over the vector. A batch costs
a few times the queue's length however many recipients it names; `PersistentStore::to_device_rows_examined` counts
the rows looked at so a test can hold that.

A standing per-recipient index in the store was rejected: `to_device_messages` is a public vector that hydration
fills with `push_back` and that tests and other code mutate, so an index would need every writer to keep it, or be
trusted only while a size check passes, and a stale index silently loses or keeps messages. One pass per batch has no
state to go stale.

One `PUT /sendToDevice` names at most `ClientApiLimits::max_send_to_device_deliveries` (1000, as inbound
`m.direct_to_device` is capped by `max_inbound_direct_to_device_deliveries`) local deliveries, a `*` counting one per
device. Over it, the request is refused with `413 M_TOO_LARGE`, nothing is queued and the transaction is not
recorded, so the client can send in smaller requests. Truncating was rejected: a silently dropped room key leaves a
device unable to read a room. The limit is a constant, not configuration: clients send to far fewer devices at once.
The local devices a request addresses are gathered in one pass over the device table, not one scan per entry.

### Negative Consequences

* A client that sends one request to more than 1000 devices must split it into several requests.

## Links

* Extends [ADR-0117](0117-bound-to-device-queues-by-recipient-count-and-age.md)
* Related [ADR-0335](0335-bound-the-to-device-queue-in-bytes-per-recipient.md)
