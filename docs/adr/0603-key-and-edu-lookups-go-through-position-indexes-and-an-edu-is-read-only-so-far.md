# Key and EDU lookups go through position indexes, and an EDU is read only so far

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `resource-exhaustion.federation-edu-sink.linear-scan-per-attacker-key-under-runtime-mutex`

## Context and Problem Statement

An inbound `m.receipt` EDU names rooms and users as the keys of JSON objects (up to 65536 per object), and an
`m.direct_to_device` EDU names users and devices the same way. For each key the sink ran an `std::ranges::any_of` over
`store.memberships`, `store.users` or `store.devices` with `runtime.mutex` held, so one signed transaction cost keys x
rows, and the per-origin rate buckets count EDUs, not keys. How should these lookups be made cheap, and how much of an
EDU should be read?

## Decision Drivers

* The cost under the runtime lock must not grow with the table or with what a remote server writes.
* ADR-0344 and ADR-0437 already index a vector by position and trust the index only while it is in step; tests and a
  few writers edit the vectors directly, and a missed writer must cost speed, never a wrong answer.
* Presence already caps the entries of its EDU (`max_inbound_presence_entries`).

## Considered Options

1. Replace each vector with a table class that owns its rows (ADR-0215, ADR-0581 style).
2. Positions beside the vector, in two small reusable index types: `RowKeyIndex` (unique key to position) and
   `RowGroupIndex` (rows sharing a key), trusted only while the row count matches (ADR-0344).
3. Keep the scans and only cap the keys read per EDU.

## Decision Outcome

Chosen option 2, together with the caps of option 3.

* `RowKeyIndex` serves `users` (by ID) and `memberships` (by room and user). `RowGroupIndex` serves `devices` and
  `device_keys` (by user), `one_time_keys` and `fallback_keys` (by user and device) and `cross_signing_keys` (by user).
  `RowGroupIndex` keeps each key's rows as a linked list over two position arrays, so removing one row by moving the
  last row into its place (ADR-0605) costs the same however many rows share the key.
* Every writer in `PersistentStore.cpp` heals a stale index first (`sync_*`) and records an append (`note_appended`);
  an erase patches the index, or rebuilds it when it was already stale (a stale index whose count happens to match the
  vector again would otherwise be trusted). Both hydration paths call `rebuild_key_indexes`.
* The EDU sink uses `has_room_membership_row`, `find_membership_row`, `find_user_row` and `for_each_user_device`.
* A receipt EDU is read for at most `max_inbound_receipt_rooms_per_edu` (512) rooms and
  `max_inbound_receipt_users_per_edu` (256) users; a to-device EDU for at most `max_inbound_direct_to_device_users`
  (1024) users and `max_inbound_direct_to_device_device_keys` (4096) device keys. The rest is dropped and logged,
  as presence does. These are fixed local policy, not configuration, and sit well above real traffic, which names the
  rooms whose read position moved.

### Negative Consequences

* As in ADR-0344, a caller that replaces a row in a vector with another of the same count leaves a stale index that
  believes an absent key. Production code does not do this; a new writer must call the `sync_*` and `note_*` pair.
* The receipt path still scans `store.receipts` for a replaced row and, with the table at its 65536 cap, for the
  oldest remote row to evict. The caps bound that to 256 scans per EDU, which is a constant, but it is not an index.
  Indexing receipts is left for a follow-up.

## Pros and Cons of the Options

### A table class per vector

* Good, because the index is correct by construction.
* Bad, because it changes every reader of five widely used vectors and many test lines for three findings.

### Caps alone

* Good, because it is tiny.
* Bad, because 512 keys x a 100000-row table is still tens of millions of comparisons per EDU, 100 EDUs per transaction.
