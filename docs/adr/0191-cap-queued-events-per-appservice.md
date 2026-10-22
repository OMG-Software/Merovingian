# Cap the events queued for one appservice and refuse the rest

* Status: accepted
* Date: 2026-10-22

Technical Story: the negative consequence recorded in
[ADR-0163](0163-appservice-delivery-is-a-durable-outbox-drained-by-one-thread.md): "The queue of an
appservice that never returns grows without bound: no row is dropped for age."

## Context and Problem Statement

ADR-0163 made delivery to an appservice a durable outbox with one row per interested event and no
expiry. A bridge that is down for good (or a registration left in place after its bridge was removed)
still has every event in every room it is interested in appended to `appservice_outbox`, and the rows
are mirrored in `PersistentStore::appservice_outbox` in memory. Left alone the table, the memory and
the startup hydration time grow with the traffic of the whole server for as long as the registration
exists, which an operator may not notice for months.

The Application Service API says the homeserver "MUST maintain a queue of transactions to send to the
application service" and "SHOULD backoff exponentially". It gives no bound and no rule for what to do
when the queue cannot be kept. Any bound therefore loses events for a bridge that returns after the
bound was hit. How should the queue be bounded, and which events are lost?

## Considered Options

* A per-appservice row cap (`appservice.max_queued_events`, default 100000); at the cap, refuse to
  queue further events for that appservice
* The same cap, but evict the oldest row to make room for the newest
* An age limit (drop rows older than N days)
* Leave it unbounded and alert on queue depth

## Decision Outcome

Chosen option: a per-appservice cap; at the cap the **newest** event is not queued.

* **`appservice.max_queued_events`**, default 100000, range 1 to 10,000,000, restart required like every
  `appservice.*` key. `enqueue_appservice_delivery` counts the rows queued for the appservice
  (`count_appservice_outbox_entries`, two binary searches over the sorted outbox, so it is cheap enough
  per event) and, when the count has reached the cap, does not write the row. Re-queuing a row that is
  already queued is still a no-op and is not counted as a drop.
* **Refuse the newest, keep the oldest.** The queue is delivered oldest first and a transaction's ID
  and contents are fixed before it is sent (ADR-0163). Keeping the oldest events keeps the part of the
  history a returning bridge was most likely to be mid-way through, and evicting the head would have to
  reason about a row that may be the pending transaction. The events not queued are the ones a bridge
  would receive last in any case.
* **It is visible.** Each refused event increments `runtime.appservice_outbox_dropped`, exposed as
  `merovingian_appservice_outbox_dropped_total{appservice_id}` next to
  `merovingian_appservice_outbox_queued{appservice_id}`. The first refusal and every thousandth after
  it is logged at warning level and audited (`appservice.outbox.full`, category `policy`, naming the
  appservice), so a bridge stuck at its cap shows up in the audit log without one line per event.
* **The spec tension.** The spec requires a queue and gives no limit, so a cap is a deliberate departure
  for the case it cannot be honoured at all: a queue that has outgrown what the server can hold. The
  default is high enough that an outage of any realistic length on any realistic deployment does not
  reach it, and the departure is announced rather than silent. An operator who needs every event for a
  bridge raises the cap, accepting the memory; an operator who wants a bridge to stop being fed removes
  its registration.

### Positive Consequences

* A dead bridge costs a bounded amount of disk and memory.
* The operator is told, by log, audit row and metric, when a bridge has lost events.

### Negative Consequences

* A bridge that returns after the cap was reached misses the events that arrived while it was at the
  cap, with no replay; it must resynchronise by other means (for example `/sync`, or its own backfill).
* A cap of 100000 rows of `(appservice_id, stream_ordering, event_id)` is a few megabytes per
  appservice in memory; a deployment with many dead registrations holds that many times over.

## Pros and Cons of the Options

### Evict the oldest

* Good, because the bridge keeps the most recent events.
* Bad, because the oldest row may be the transaction already fixed on the cursor, and a bridge
  mid-way through a history would find a gap in the middle of it instead of at the end.

### Age limit

* Good, because it is independent of traffic.
* Bad, because it needs a clock and a reaper, and a busy server can still reach a very large queue
  well inside any age that is long enough to be useful.

### Unbounded plus an alert

* Good, because nothing is lost.
* Bad, because the first sign of the problem is the server running out of disk or memory, and the
  audit that ADR-0163 left as an operator task is the whole defence.

## Links

* Refines [ADR-0163](0163-appservice-delivery-is-a-durable-outbox-drained-by-one-thread.md)
* Spec: `docs/matrix-v1.19-spec/application-service-api.md`, "Pushing events"
* Compare [ADR-0173](0173-cap-global-account-data-types-per-user.md): a per-owner row cap with a
  configuration key
