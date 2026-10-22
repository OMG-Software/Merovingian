# Appservice ephemeral data is in memory, bounded, coalesced and best-effort

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit finding R08. `receive_ephemeral` was parsed from the registration
file and then ignored: no `m.typing`, `m.receipt` or `m.presence` data was ever sent to an
appservice.

## Context and Problem Statement

The Application Service API says that "if the `receive_ephemeral` settings is enabled in the
registration file, homeservers MUST send ephemeral data that is relevant to the application service
via the transaction API, using the `ephemeral` property of the request's body." Three event types
exist, each with its own relevance rule (typing and receipts "under the same rules as regular
events", private read receipts only for users in the appservice's namespaces, presence "if the data
would apply contextually"). The spec says nothing about retrying, ordering or surviving an outage for
ephemeral data, whereas the regular events of a transaction "MUST" be queued, and ADR-0163 made that
queue a durable outbox.

Ephemeral data is far more frequent than events: a typing indicator is re-sent every few seconds, and
every read receipt and presence change is one. Should it ride the durable outbox, or be best-effort?

## Considered Options

* Best-effort: hold it in memory per appservice, bounded and coalesced, and attach it to the next
  transaction
* Durable: write each item to an `appservice_ephemeral_outbox` table and drain it like events
* Reuse the event outbox by giving ephemeral items synthetic stream orderings

## Decision Outcome

Chosen option: best-effort, in memory.

* **Why loss is acceptable.** Ephemeral data describes the present. A typing indicator that is a minute
  old is false, a presence state that has since changed is wrong, and a read receipt is superseded by
  the user's next one. The state is re-announced by the next change. The spec obliges the homeserver to
  *send* relevant ephemeral data; it does not oblige it to survive an outage, and its retry language
  ("MUST maintain a queue of transactions") is about the events of ADR-0163.
* **Coalesced by what it describes.** Each item has a key (one room's typing list, one user's
  presence, one user's receipt of one type in one thread). A newer item replaces the older item with the
  same key, so the queue holds the latest fact per key, not a history. A chatty room therefore cannot
  fill the queue with states that were already superseded.
* **Bounded.** At most `max_appservice_ephemeral_queue` (512) items are queued per appservice; at the
  cap the oldest is dropped and counted (`merovingian_appservice_ephemeral_dropped_total`). A
  transaction carries at most `max_appservice_ephemeral_per_transaction` (100) items. A presence change
  makes at most `max_appservice_presence_member_checks` (20000) member-against-namespace matches
  across all appservices, because "shares a room with" would otherwise cost a regex match per member
  of every room the subject is in, under `runtime.mutex`, per update (compare ADR-0173 to ADR-0176).
  Finding the rooms the subject is in is a string comparison and is not charged: charging it let the
  rooms the subject is *not* in exhaust the budget on any server with more than 20000 memberships, so
  shared-room presence silently stopped. Past the budget an appservice may miss that one update.
* **Profile changes.** The `m.presence` a display name or avatar change sends (Client-Server API,
  "Events on change of profile information") is queued like any other presence change.
* **Rides the drainer.** Ephemeral items are attached to the next transaction `drain_appservice_queues`
  sends. When no event is queued, an events-free transaction carries them alone, under a fresh
  transaction ID taken from the cursor's `next_txn_id` (persisted, so the ID is never reused) with no
  pending marker. The items of a transaction in flight are kept in memory (`AppservicePendingEphemeral`)
  so a retry under the same ID carries exactly the same items, honouring "MUST NOT alter ... events
  they were going to send within that transaction ID on retries"; after a restart a re-sent event
  transaction carries its event alone.
* **Hooks.** Typing is queued from `update_room_typing_stream_id_if_changed`, the one function every
  typing change passes through (local, federated, cleared by a message send). Receipts are queued
  after `store_receipt` succeeds, locally and from a federation EDU. Presence is queued after
  `upsert_presence` succeeds, locally and from a federation EDU. An appservice with `url: null`
  receives nothing.

### Positive Consequences

* No database write behind a typing indicator, and the outbox stays one event per transaction.
* A dead bridge costs at most 512 small items, not a growing table.

### Negative Consequences

* Ephemeral data sent while a bridge is down, or lost to a restart, is not redelivered. This is a
  deliberate reading of the spec, not an oversight.
* A presence update by a user in very many large rooms may not reach an appservice that shares only a
  later room with them.
* A transaction that carries ephemeral data is not identical to one rebuilt after a restart.

## Pros and Cons of the Options

### Durable ephemeral outbox

* Good, because nothing relevant is lost to an outage.
* Bad, because it adds a database write per typing, receipt and presence change per interested
  appservice, and replays stale typing and presence state to a bridge that comes back an hour later.

### Synthetic stream orderings in the event outbox

* Good, because it needs no new queue.
* Bad, because ephemeral items have no event row (the drainer rebuilds a transaction from a stored
  event), and the primary key `(appservice_id, stream_ordering)` would collide with real orderings.

## Links

* Spec: `docs/matrix-v1.19-spec/application-service-api.md`, "Pushing ephemeral data"
* Refines [ADR-0163](0163-appservice-delivery-is-a-durable-outbox-drained-by-one-thread.md)
* `include/merovingian/homeserver/appservice_ephemeral.hpp`
