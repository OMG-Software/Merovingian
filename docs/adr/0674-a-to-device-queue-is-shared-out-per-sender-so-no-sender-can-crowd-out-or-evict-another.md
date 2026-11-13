# A to-device queue is shared out per sender, so no sender can evict or crowd out another

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

Technical Story: run-3 audit finding C12, any sender evicting a victim's pending room keys by filling the victim's to-device queue

## Context and Problem Statement

A recipient's to-device queue is bounded per device and per user (ADR-0335, ADR-0618). A message that would pass a bound
evicted the oldest queued rows, whoever had sent them. Any local user, and any federated server, can send to any local user's
devices, so about 256 messages of 64 KiB deleted every Olm-encrypted `m.room_key` delivery other senders had queued for a
device that had not yet synced. The device could then no longer decrypt the room messages those keys protect. The invariant to
keep is that no sender (a local user, or a remote server for everything its users send) can stop another sender's message from
being delivered, either by evicting it or by occupying the space it needs. How is a bounded queue shared out so that holds,
without bringing back ADR-0618's stale-device backlog?

## Decision Drivers

* One sender must not cause the eviction of another sender's queued messages.
* One sender must not be able to fill the queue first and so make later senders' messages fail.
* ADR-0618: a user's oldest row goes first, whichever device holds it, so a stale device's backlog cannot hold the user's budget.
* The work under `runtime.mutex` must not grow with what a sender chooses: logarithmic or constant per enqueue, no scan of a queue.

## Considered Options

* Per-sender fair share: a sender may hold at most half of a bound once another sender is queued, a message from a sender at
  its share evicts that sender's own oldest row, and a full bound gives way to a sender under its share by evicting the oldest
  row of the largest holder
* A message evicts only its own sender's oldest rows, and is dropped when it has none
* Refuse a sender that holds more than a fair share
* A per-(sender, recipient) rate limit

## Decision Outcome

Chosen option: "Per-sender fair share".

A row is charged to its sender's user ID when the sender is on this server, and to the sender's server otherwise
(`to_device_share_of`): a remote server chooses the user IDs it sends as, so charging users would let one server split its
share. For each bound (a device's queue, and all of a user's queues) the batch builds a `ShareBook` from the rows held: each
sender's row count, bytes and rows by stream ID, and a ranking of the senders by how much of the bound each holds (the larger of
its row and byte fractions, then rows, then the sender with the older oldest row). Adding a row, removing one and picking the
largest holder or a sender's oldest row are logarithmic in the number of senders; a queue is never scanned. A binary search
finds the row in its queue, which is in stream order.

A message first makes the sender's own share fit: while another sender is queued and the message would take the sender past half
of the bound, the sender's own oldest row goes (at the user bound, whichever device holds it, which is ADR-0618's rule per
sender). A sender alone in a queue may use all of it, so a single sender is bounded exactly as before. Then, while the bound is
still full, the oldest row of the largest holder goes. The incoming message is always stored: a sender under its share never has a
message dropped, and no row of a sender is evicted except to make room for a sender holding less, or for the same sender. The
book is built from the rows at the start of each batch, so it is right after a restart, an acknowledgement or a hydration with no
index to maintain.

### Rejected: evicting only the sender's own rows and dropping the message when it has none (the first C12 fix)

It keeps the finding's literal invariant (a sender never removes another's row) but reverses the denial: whoever fills a queue
first makes every later sender's message, room keys included, be dropped. An attacker would simply send first. The invariant
that matters is that no sender can stop another's delivery, whether by evicting or by occupying the space.

### Rejected: a fair-share refusal

It needs a threshold above which a sender is refused, and refusing is again a drop of a message from a sender that did nothing
wrong when the queue is full of someone else's rows. Eviction from the largest holder never refuses.

### Rejected: a per-(sender, recipient) rate

It does not stop a sender from filling a queue within the rate, only from filling it quickly.

### Negative Consequences

* A sender that shares a queue with another sender can hold at most half of its bound, where before it could hold all of it. A
  sender alone is unchanged.
* Eviction from a deque erases from the middle of a queue (a memory move of at most the per-device row limit); each row is
  evicted once, so a request's total is bounded by the rows it adds plus the rows it evicts times that limit.
* A large sender at its share loses its own oldest row to a new message of its own even though the queue has room, if another
  sender is present. That is the price of the guarantee and is bounded by the sender's own share.
