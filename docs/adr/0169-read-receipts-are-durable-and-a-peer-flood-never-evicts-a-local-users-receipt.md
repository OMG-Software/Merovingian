# Read receipts are durable, and a peer's flood never evicts a local user's receipt

* Status: accepted
* Date: 2026-10-19

## Context and Problem Statement

Read receipts were held only in `HomeserverRuntime::receipts`, in memory. Every unread count
(`/sync` `unread_notifications`, sliding sync `notification_count`, the room-list sort, the
push-gateway badge, `GET /notifications` `read`) is computed from them. A restart therefore
forgot every user's read position: rooms the user had read came back unread. That is what
users saw as "I mark a room read and when I reopen the app it is unread again". Other members
also lost the public receipts they had been shown.

The same collection was capped against federation floods (0.12.5 audit, finding 13) by
evicting its oldest entry. Once a local user's receipt is the only record of where they have
read up to, evicting it is not freeing stale ephemeral state. It marks a room unread for that
user, and a remote peer can trigger it.

The spec makes receipts part of the user's notification state: "When the user updates their
read receipt ... notifications prior to and including that event MUST be marked as read". It
does not say where a server keeps them. That is this decision.

## Considered Options

* Keep receipts in memory only.
* Persist receipts in a `receipts` table (migration 024), mirrored in
  `PersistentStore::receipts`, with the existing cap evicting the oldest receipt of any user.
* Persist receipts as above, and let the cap evict only the oldest receipt of a remote user.

## Decision Outcome

Chosen option: persist receipts, and let the cap evict only the oldest receipt of a remote
user. Each row's primary key is `(room_id, receipt_type, user_id, thread_id)`, the spec's
"Each user_id, receipt_type, and categorisation (unthreaded, or thread_id) tuple must be
associated with only a single event_id". `thread_id` is `''` for an unthreaded receipt.

Rules for future code:

* Write receipts only through `database::store_receipt` and `database::remove_receipt`. They
  commit the row before the mirror changes, and `store_receipt` allocates the sync stream
  position. Never `push_back` into `PersistentStore::receipts` outside tests.
* `HomeserverRuntime` holds no receipts of its own. Read them from
  `database.persistent_store.receipts`.
* The inbound cap (`max_inbound_receipt_entries`) never removes a local user's receipt. If
  every receipt held belongs to a local user, the new remote receipt is stored over the cap.
  The real bound is still the membership check in front of it.
* The table is main-process only. The federation worker relays receipt EDUs and never
  computes unread counts, so it is not in `federation_worker_table_allowlist`.

### Positive Consequences

* Read state survives restarts, upgrades and crashes, so clients get correct unread counts on
  an initial sync.
* A peer flooding a large room can no longer change a local user's unread state.

### Negative Consequences

* Every receipt, local or federated, is now a database write. Receipts arrive often in busy
  rooms. Each write is one upsert of one row, the same cost as an account-data write.
* The row count is bounded by rooms × members × receipt types × threads, not by a fixed cap,
  for local users.

## Pros and Cons of the Options

### Keep receipts in memory only

* Good, because there is no write per receipt.
* Bad, because a restart marks every room unread for every user. This is the reported bug.

### Persist, evict the oldest receipt of any user

* Good, because the memory bound is a hard number.
* Bad, because a remote peer can evict a local user's read position, which is now durable
  user state rather than a cache.

## Links

* Refines the receipt cap of the 0.12.5 audit, finding 13 (`include/merovingian/homeserver/runtime.hpp`)
