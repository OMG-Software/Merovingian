# To-device transaction records are kept for seven days, and a client-chosen key part is at most 255 bytes

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-54

## Context and Problem Statement

Every `PUT /sendToDevice/{eventType}/{txnId}` with a fresh transaction ID commits a `client_txn_ids` row and appends the same
record and an index entry to memory, even for an empty `messages` object. Nothing removed them, both backends reload them all at
start-up, and the event type and transaction ID had no length bound other than the 8192-byte start line, so one account could
make the server keep about 16 KB of heap per request for ever. The spec asks only that a retransmission be recognised; it names
no retention period.

## Decision Drivers

* Memory and disk must not grow without bound because of requests (the driver of ADR-0117).
* ADR-0258 serves `unsigned.transaction_id` from the room-send rows, so those must stay.
* Work under `runtime.mutex` must be bounded.

## Considered Options

* Delete to-device records older than 7 days, from the database and the mirror, in an hourly job; bound the event type and transaction ID at 255 bytes
* A per-user cap on records
* Prune every record, room sends included

## Decision Outcome

Chosen option: "delete to-device records older than 7 days, and bound the key parts", the owner's decision.

* `client_txn_ids` gains `created_at_ms` (the store stamps it). `database::prune_to_device_client_txns(store, cutoff_ms)` deletes
  rows with `room_id` empty and a time before the cutoff in one statement, erases them from `client_txn_ids` and rebuilds
  `client_txn_event_index` and `client_txn_key_index`, which hold vector positions. Room-send and redact rows are never touched.
* The `client-txn-prune` `PeriodicJob` runs `homeserver::prune_client_transactions` at start and then every hour. The sweep
  takes `runtime.mutex` for one linear pass over the table, and for the index rebuild only when it removed something. It is
  linear in the rows the server holds, not in anything a request chooses, and the interval keeps it to once an hour.
* `txnId` over 255 bytes is refused with `400 M_INVALID_PARAM` on `/send`, `/redact` and `/sendToDevice`, as is
  `eventType` on `/sendToDevice`, before the idempotency lookup. `eventType` on `/send` is a room event's type, under the
  spec's size limits, and keeps the `413 M_TOO_LARGE` already decided for those.

### Positive Consequences

* The to-device rows, the only ones a request can create without a stored event behind them, stop growing for ever.
* A key part cannot make a row larger than a few hundred bytes.

### Negative Consequences

* A `sendToDevice` retransmission that arrives more than 7 days after the original is delivered a second time. This is accepted:
  a client does not retry for a week, and the messages are the same ones.
* Room-send rows still grow with the events stored, as ADR-0258 says.
* The sweep holds `runtime.mutex` for a pass over the whole table once an hour; on a very large table that is a pause. If it
  becomes one, the table needs an index by age, not a longer interval.

## Pros and Cons of the Options

### A per-user cap on records

* Good, because it bounds one account's share.
* Bad, because a cap that refuses a request makes a legitimate send fail, and it does not return memory.

### Prune every record

* Good, because the table would be bounded.
* Bad, because `unsigned.transaction_id` is served from the room-send rows and would stop working for older events.

## Links

* Refines [ADR-0258](0258-unsigned-transaction-id-goes-to-the-sending-device.md): its "`client_txn_ids` is never pruned" no longer holds for to-device rows
* Related to [ADR-0117](0117-bound-to-device-queues-by-recipient-count-and-age.md)
