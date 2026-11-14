# Receipts are read through room and user indexes, and a threaded receipt must be related to its thread

* Status: Accepted (its admission rule for a threaded receipt is amended by [ADR-0746](0746-a-threaded-receipt-may-name-any-event-whose-relation-chain-reaches-the-root.md))
* Date: 2026-11-12

Technical Story: run-3 audit finding C23 (receipt rows grow without bound and every reader scans the whole table).

## Context and Problem Statement

`store.receipts` was one vector. Classic `/sync` scanned all of it twice per joined room (the ephemeral `m.receipt`
events and the read markers behind the unread counts), the push badge count scanned it once per pusher recipient of
each event, the sliding-sync receipts extension and its wake check scanned it, and `store_receipt` did a `find_if` over
it per write, all under `runtime.mutex`. The POST receipt handler accepted a `thread_id` that named any event of the
room that is in the main timeline, so one user could keep two rows per event of any room, with no cap, and make every
other user pay for them on every sync.

## Decision Drivers

* No work under `runtime.mutex` may grow with what a low-trust account chooses.
* The spec allows 400 `M_INVALID_PARAM` when "the `event_id` is not related to the `thread_id`".
* The existing row indexes (ADR-0344, ADR-0437, ADR-0603) already solve the read side.

## Considered Options

* Two `RowGroupIndex`es (by room, by room and user), a relatedness check on `thread_id`, and a per-(user, room) cap
  that evicts the user's own oldest threaded row.
* Only the cap and the indexes, keeping the old "thread_id names any main-timeline event" admission rule.
* A cap on all receipt rows of a room.
* A per-user index as well.

## Decision Outcome

Chosen option: the first.

* `receipt_room_index` and `receipt_user_room_index` sit beside `receipts`, with the trust rule of ADR-0603 (used only
  while built for the vector's current row count, else a reader scans). `store_receipt` and `remove_receipt` keep them
  in step, an erase moves the last row into the gap (so the vector has no order), and `rebuild_key_indexes` rebuilds
  them after hydration on both backends. Readers use `receipts_in_room` and `receipts_of_user_in_room`, never the
  vector, and `receipt_rows_examined` counts the rows they read so tests can prove the cost.
* A receipt filed under a thread root is accepted when the receipted event is the root, or reaches it through
  `sync::event_thread_id` (an `m.thread` relation, up to the spec's three hops). An event this server does not hold in
  the room is related to nothing. The old rule let a user choose the `thread_id` freely among thousands of events.
* `store_receipt` holds at most `max_threaded_receipt_rows_per_user_room` (256) rows whose `thread_id` is neither empty
  nor `main` for one (user, room), counting `m.read` and `m.read.private` rows alike. A new threaded row past the cap is
  committed in the same transaction as the delete of that user's own oldest threaded row (lowest `stream_id`). The
  cap is in the store, not the handler, so the federation sink is bound by it too. Unthreaded and `main` rows, and every
  other user's rows, are never evicted by it.
* No per-user index: no reader needs one. The sliding-sync wake check walks the joined rooms' rows.

### Negative Consequences

* A client that sends threaded receipts for more than 128 threads in one room (per receipt type) loses the receipt of
  its oldest thread. Its unread count for that thread falls back to the unthreaded receipt, which is the safe side.
* A threaded receipt for an event this server does not hold is now refused, where an unthreaded one is still accepted.

## Pros and Cons of the Options

### Only the cap and the indexes

* Good, because it changes no behaviour a client sees.
* Bad, because the cap alone leaves the user free to choose which of thousands of events to name; the relatedness
  rule is what the spec asks for and it makes the choice the event's own.

### A cap on all receipt rows of a room

* Bad, because a large room's honest rows (one per member) would be evicted by other members' receipts.

## Links

* Refines ADR-0603 and ADR-0437 (position indexes), ADR-0617 (unread rows examined).
